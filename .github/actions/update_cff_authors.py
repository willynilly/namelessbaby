import os
import re
import requests
import yaml
import json
from pathlib import Path


def get_github_session(token):
    session = requests.Session()
    session.headers.update(
        {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    )
    return session


def get_linked_issues(session, repo, pr_number):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/timeline"
    headers = {"Accept": "application/vnd.github.mockingbird-preview+json"}
    response = session.get(url, headers=headers)
    if response.status_code != 200:
        return []
    data = response.json()
    return [
        event["source"]["issue"]["number"]
        for event in data
        if event.get("event") == "cross-referenced"
        and event.get("source", {}).get("issue", {}).get("pull_request") is None
    ]


def collect_metadata_contributors(token, repo, pr_number, flags):
    session = get_github_session(token)
    contributors = set()

    if flags.get("authorship_for_pr_reviews"):
        reviews_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
        for review in session.get(reviews_url).json():
            user = review.get("user", {}).get("login")
            if user:
                contributors.add(user)

    if flags.get("authorship_for_pr_comment"):
        comments_url = (
            f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        )
        for comment in session.get(comments_url).json():
            user = comment.get("user", {}).get("login")
            if user:
                contributors.add(user)

    if flags.get("authorship_for_pr_issues") or flags.get(
        "authorship_for_pr_issue_comments"
    ):
        linked_issues = get_linked_issues(session, repo, pr_number)
        for issue_number in linked_issues:
            if flags.get("authorship_for_pr_issues"):
                issue_url = f"https://api.github.com/repos/{repo}/issues/{issue_number}"
                issue = session.get(issue_url).json()
                author = issue.get("user", {}).get("login")
                if author:
                    contributors.add(author)

            if flags.get("authorship_for_pr_issue_comments"):
                comments_url = f"https://api.github.com/repos/{repo}/issues/{issue_number}/comments"
                for comment in session.get(comments_url).json():
                    user = comment.get("user", {}).get("login")
                    if user:
                        contributors.add(user)

    return contributors


def collect_commit_contributors(token, repo, base, head, include_coauthors=True):
    url = f"https://api.github.com/repos/{repo}/compare/{base}...{head}"
    headers = {"Authorization": f"token {token}"}
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    data = r.json()
    commits = data.get("commits", [])
    contributors = set()
    coauthor_regex = re.compile(r"^Co-authored-by:\s*(.+?)\s*<(.+?)>$", re.IGNORECASE)
    for c in commits:
        author = c.get("author")
        commit_author = c.get("commit", {}).get("author", {})
        if author and author.get("login"):
            contributors.add(author["login"])
        elif commit_author:
            name = commit_author.get("name")
            email = commit_author.get("email")
            if name or email:
                contributors.add((name, email))

        if include_coauthors:
            for line in c.get("commit", {}).get("message", "").splitlines():
                match = coauthor_regex.match(line.strip())
                if match:
                    name, email = match.groups()
                    if name or email:
                        contributors.add((name.strip(), email.strip()))
    return sorted(contributors)


def extract_orcid(text):
    if not text:
        return None
    match = re.search(r"https?://orcid\.org/(\d{4}-\d{4}-\d{4}-\d{4})", text)
    return match.group(1) if match else None


def validate_orcid(orcid):
    if not orcid or not re.match(r"^\d{4}-\d{4}-\d{4}-\d{4}$", orcid):
        return False
    url = f"https://pub.orcid.org/v3.0/{orcid}"
    headers = {"Accept": "application/json"}
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def search_orcid(full_name, email=None, logs=None):
    headers = {"Accept": "application/vnd.orcid+json"}
    name_parts = full_name.strip().split(" ", 1)
    given = name_parts[0]
    family = name_parts[1] if len(name_parts) > 1 else ""
    query = f"given-names:{given}"
    if family:
        query += f" AND family-name:{family}"
    if email:
        query += f' OR email:"{email}"'
    url = f"https://pub.orcid.org/v3.0/search/?q={query}"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        results = resp.json()
        if "result" in results and results["result"]:
            match = results["result"][0]
            orcid_id = match["orcid-identifier"]["path"]
            rec_url = f"https://pub.orcid.org/v3.0/{orcid_id}/personal-details"
            rec_resp = requests.get(rec_url, headers=headers, timeout=5)
            rec_resp.raise_for_status()
            details = rec_resp.json()

            credit_name = details.get("credit-name", {}).get("value", "")
            other_names = [
                n["content"]
                for n in details.get("other-names", {}).get("other-name", [])
            ]
            given_name = details.get("given-names", {}).get("value", "")
            family_name = details.get("family-name", {}).get("value", "")
            combined = f"{given_name} {family_name}".strip()

            target = full_name.strip().lower()
            possibilities = (
                [credit_name.strip().lower()]
                + [n.strip().lower() for n in other_names]
                + [combined.lower()]
            )
            if target in possibilities:
                log = f"- `{full_name}` matched to ORCID `{orcid_id}` (record name: **{credit_name or combined}**)"
                if logs is not None:
                    logs.append(log)
                return orcid_id
            else:
                if logs is not None:
                    logs.append(
                        f"- `{full_name}`: ORCID `{orcid_id}` found but name mismatch"
                    )
    except Exception as e:
        if logs is not None:
            logs.append(f"- `{full_name}`: ORCID search failed: {e}")
    return None


def main():
    repo = os.environ["REPO"]
    token = os.environ["GITHUB_TOKEN"]
    base = os.environ["BASE_BRANCH"]
    head = os.environ["HEAD_BRANCH"]
    cff_path = os.environ.get("CFF_PATH", "CITATION.cff")
    output_file = os.environ.get("GITHUB_OUTPUT", "/tmp/github_output.txt")
    pr_number = None
    if os.path.exists(os.environ.get("GITHUB_EVENT_PATH", "")):
        with open(os.environ["GITHUB_EVENT_PATH"], "r") as f:
            event = json.load(f)
            pr_number = event.get("number") or event.get("pull_request", {}).get(
                "number"
            )

    flags = {
        "commits": os.environ.get("AUTHORSHIP_FOR_PR_COMMITS", "true").lower()
        == "true",
        "reviews": os.environ.get("AUTHORSHIP_FOR_PR_REVIEWS", "true").lower()
        == "true",
        "issues": os.environ.get("AUTHORSHIP_FOR_PR_ISSUES", "true").lower() == "true",
        "issue_comments": os.environ.get(
            "AUTHORSHIP_FOR_PR_ISSUE_COMMENTS", "true"
        ).lower()
        == "true",
        "pr_comments": os.environ.get("AUTHORSHIP_FOR_PR_COMMENT", "true").lower()
        == "true",
        "include_coauthors": os.environ.get("INCLUDE_COAUTHORS", "true").lower()
        == "true",
        "post_comment": os.environ.get("POST_COMMENT", "true").lower() == "true",
    }

    contributors = set()
    if flags["commits"]:
        contributors.update(
            collect_commit_contributors(
                token, repo, base, head, flags["include_coauthors"]
            )
        )
    if pr_number:
        metadata_flags = {
            "authorship_for_pr_reviews": flags["reviews"],
            "authorship_for_pr_issues": flags["issues"],
            "authorship_for_pr_issue_comments": flags["issue_comments"],
            "authorship_for_pr_comment": flags["pr_comments"],
        }
        contributors.update(
            collect_metadata_contributors(token, repo, pr_number, metadata_flags)
        )
        process_contributors(
            contributors, cff_path, token, repo, pr_number, output_file, flags
        )


def process_contributors(
    contributors, cff_path, token, repo, pr_number, output_file, flags
):

    path = Path(cff_path)
    if not path.exists():
        print(f"{cff_path} not found.")
        return

    with open(path, "r") as f:
        cff = yaml.safe_load(f)

    cff.setdefault("authors", [])

    new_users = []
    warnings = []
    logs = []

    def is_same_person(a, b):
        return (
            a.get("alias", "").lower() == b.get("alias", "").lower()
            or a.get("email", "").lower() == b.get("email", "").lower()
            or a.get("orcid", "").lower() == b.get("orcid", "").lower()
            or (
                f"{a.get('given-names', '').strip().lower()} {a.get('family-names', '').strip().lower()}"
                == f"{b.get('given-names', '').strip().lower()} {b.get('family-names', '').strip().lower()}"
            )
        )

    for contributor in contributors:
        entry = {}
        identifier = ""
        if isinstance(contributor, str):
            user_url = f"https://api.github.com/users/{contributor}"
            resp = requests.get(user_url, headers={"Authorization": f"token {token}"})
            if resp.status_code != 200:
                continue
            user = resp.json()
            user_type = user.get("type")

            if user_type == "Organization":
                entry["name"] = user.get("name") or contributor
                entry["alias"] = contributor
                entry["type"] = "entity"
                if user.get("email"):
                    entry["email"] = user["email"]
            else:
                full_name = user.get("name") or contributor
                name_parts = full_name.split(" ", 1)
                entry["given-names"] = name_parts[0]
                entry["family-names"] = name_parts[1] if len(name_parts) > 1 else ""
                entry["alias"] = contributor
                entry["type"] = "person"
                if user.get("email"):
                    entry["email"] = user["email"]
                orcid = extract_orcid(user.get("bio"))
                if not orcid and full_name:
                    orcid = search_orcid(full_name, user.get("email"), logs)
                if orcid and validate_orcid(orcid):
                    entry["orcid"] = f"https://orcid.org/{orcid}"
                elif orcid:
                    warnings.append(
                        f"- @{contributor}: ORCID `{orcid}` is invalid or unreachable."
                    )
                else:
                    warnings.append(f"- @{contributor}: No ORCID found.")

            identifier = contributor.lower()

        else:
            name, email = contributor
            name_parts = name.split(" ", 1)
            full_name = name
            entry_type = "entity"
            matched = False

            for existing in cff["authors"]:
                if (
                    "given-names" in existing
                    and "family-names" in existing
                    and "email" in existing
                ):
                    existing_name = f"{existing['given-names']} {existing['family-names']}".strip().lower()
                    if (
                        existing_name == name.strip().lower()
                        and existing["email"].strip().lower() == email.strip().lower()
                    ):
                        entry["given-names"] = existing["given-names"]
                        entry["family-names"] = existing["family-names"]
                        entry["email"] = existing["email"]
                        if "orcid" in existing:
                            entry["orcid"] = existing["orcid"]
                        entry_type = "person"
                        matched = True
                        break

            if entry_type == "entity" and not matched:
                entry["name"] = name
                if email:
                    entry["email"] = email
                entry["type"] = "entity"
                if user.get("email"):
                    entry["email"] = user["email"]
            else:
                entry["given-names"] = name_parts[0]
                entry["family-names"] = name_parts[1] if len(name_parts) > 1 else ""
                if email:
                    entry["email"] = email
                entry["type"] = "person"
                orcid = search_orcid(full_name, email, logs)
                if orcid and validate_orcid(orcid):
                    entry["orcid"] = f"https://orcid.org/{orcid}"
                elif orcid:
                    warnings.append(
                        f"- `{full_name}`: ORCID `{orcid}` is invalid or unreachable."
                    )
                else:
                    warnings.append(f"- `{full_name}`: No ORCID found.")
            identifier = email or name.lower()

        if any(is_same_person(a, entry) for a in cff["authors"]):
            warnings.append(f"- {identifier}: Already exists in CFF file.")
            continue

        cff["authors"].append(entry)
        new_users.append(identifier)

    with open(cff_path, "w") as f:
        yaml.dump(cff, f, sort_keys=False)

    with open(output_file, "a") as f:
        f.write(f"new_users={','.join(new_users)}\n")
        f.write("updated_cff<<EOF\n")
        f.write(yaml.dump(cff, sort_keys=False))
        f.write("\nEOF\n")
        if warnings:
            f.write("warnings<<EOF\n" + "\n".join(warnings) + "\nEOF\n")
        if logs:
            f.write("orcid_logs<<EOF\n" + "\n".join(logs) + "\nEOF\n")

    if flags["post_comment"] and pr_number:
        marker = "<!-- contributor-check-comment -->"
        timestamp = (
            requests.get("https://worldtimeapi.org/api/timezone/Etc/UTC")
            .json()
            .get("datetime", "")[:16]
            .replace("T", " ")
        )
        commit_sha = os.environ.get("GITHUB_SHA", "")[:7]
        comment_body = f"""{marker}
### New Authors Detected

**New GitHub Users or Commit Authors:**
{chr(10).join(f"- {u}" for u in new_users) if new_users else "_None_"}

**Updated `{cff_path}` file:**
```yaml
{yaml.dump(cff, sort_keys=False)}
```
"""

        if warnings:
            comment_body += "\n**Warnings & Recommendations:**\n" + "\n".join(warnings)

        if logs:
            comment_body += f"""

<details>
<summary><strong>ORCID Match Details</strong></summary>

{chr(10).join(logs)}

</details>"""

        comment_body += f"""

_Last updated: {timestamp} UTC · Commit `{commit_sha}`_
"""

        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        }
        comments_url = (
            f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        )
        existing = requests.get(comments_url, headers=headers).json()
        existing_comment = next(
            (c for c in existing if marker in c.get("body", "")), None
        )

        payload = {"body": comment_body}
        if existing_comment:
            comment_id = existing_comment["id"]
            requests.patch(
                f"{comments_url}/{comment_id}", headers=headers, json=payload
            )
        else:
            requests.post(comments_url, headers=headers, json=payload)


if __name__ == "__main__":
    main()
