# Results (generated, do not edit)

## Held-out test corpus

| Configuration | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| regex | 0.851 | 0.905 | 0.877 | 497 | 87 | 52 |
| entropy | 0.590 | 0.696 | 0.639 | 382 | 265 | 167 |
| combined | 0.608 | 0.995 | 0.755 | 546 | 352 | 3 |
| combined+classifier | 0.909 | 0.925 | 0.917 | 508 | 51 | 41 |
| gitleaks | 0.940 | 0.741 | 0.829 | 407 | 26 | 142 |
| trufflehog | 1.000 | 0.375 | 0.546 | 206 | 0 | 343 |

## Train corpus (secrety only)

| Configuration | Precision | Recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| regex | 0.778 | 0.902 | 0.836 | 488 | 139 | 53 |
| entropy | 0.676 | 0.689 | 0.683 | 373 | 179 | 168 |
| combined | 0.629 | 0.996 | 0.771 | 539 | 318 | 2 |
| combined+classifier | 0.996 | 0.921 | 0.957 | 498 | 2 | 43 |

## Decoy families on the test corpus

| Family | Flagged without classifier | Flagged with classifier |
| --- | ---: | ---: |
| git_sha | 49/49 | 0/49 |
| uuid | 0/34 | 0/34 |
| checksum | 49/49 | 0/49 |
| placeholder_password | 30/30 | 0/30 |
| dotted_reference | 34/45 | 0/45 |
| data_uri_chunk | 43/43 | 1/43 |
| public_identifier | 3/50 | 2/50 |
| env_var_name | 23/37 | 0/37 |
| integrity_hash | 45/45 | 0/45 |
| docker_digest | 28/28 | 0/28 |
| ssh_public_key | 40/40 | 40/40 |
| asset_name | 8/28 | 8/28 |

## Secret families on the test corpus

| Family | Found without classifier | Found with classifier |
| --- | ---: | ---: |
| aws_access_key | 47/47 | 47/47 |
| github_token | 51/51 | 51/51 |
| stripe_key | 54/54 | 54/54 |
| google_api_key | 57/57 | 57/57 |
| slack_token | 51/51 | 51/51 |
| jwt | 55/55 | 55/55 |
| password | 46/46 | 46/46 |
| url_credentials | 45/45 | 45/45 |
| private_key | 52/52 | 52/52 |
| aws_secret_key | 39/39 | 39/39 |
| entropy_token | 49/52 | 11/52 |

## Time on 1500 files (median of 3 runs, whole process)

| Tool | Seconds |
| --- | ---: |
| secrety (combined) | 2.55 |
| gitleaks | 1.38 |
| trufflehog | 1.79 |

Versions: gitleaks 8.30.1, trufflehog 3.100.0 (trufflehog with `--no-verification`).
