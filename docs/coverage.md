# Coverage and validation matrix

Implementation, fixture presence, CI results and physical-device validation are
different claims. `security-audit coverage --format json` returns this matrix
without inspecting the host. Fixture entries describe tests included in the
source; see Actions for execution results for the exact commit.

| OS/version | Browser | Implemented scope | Synthetic fixtures | Physical-device record |
| --- | --- | --- | --- | --- |
| macOS adapter | Chrome (version unrecorded) | Presence; bounded manifest declarations; aggregate user review | Declaration fields, scope, manual states; bounds/redaction tests also run cross-platform | Historical general Mac scan only; Chrome-specific version/scope unrecorded |
| macOS adapter | Brave / Edge | Presence; bounded extension directory counts; aggregate user review | Separate browser directory/scope cases | No documented browser-specific device run |
| macOS adapter | Firefox / Safari | Data-directory presence; aggregate user review | Separate browser directory/scope cases | No documented browser-specific device run |
| Windows 10/11 adapter | Chrome (version unrecorded) | Presence; bounded manifest declarations; selected registry policies; aggregate user review | Manifest/registry parser, malformed/conflicting states, bounds/redaction and manual states | Historical Windows OS/browser/UI run; browser version and full scope unrecorded |
| Windows 10/11 adapter | Brave / Edge | Presence; bounded extension directory counts; aggregate user review | Separate browser directory/scope cases | No documented browser-specific device run |
| Windows 10/11 adapter | Firefox | Data-directory presence; aggregate user review | Separate browser directory/scope cases | No documented browser-specific device run |
| Windows | Safari | No discovery adapter; independent manual guidance only | No automatic adapter fixture | None |
| macOS adapter | OS/network | Selected hardening settings and non-loopback TCP listeners | Command states (enabled/disabled/malformed/nonzero), sandbox and listener reduction | 2026-10-06 one Mac, macOS 27.2/Python 3.11.4, old commit 20332630… |
| Windows 10/11 adapter | OS/network | Selected hardening settings and non-loopback TCP listeners | On/off/passive/unknown states, listener validation; Windows CI local probe shapes | 2026-10-06 one PC, OS/Python/source version unrecorded in that note |
| Linux / other | OS/network/browser | Adapters unavailable | Unsupported-platform fixtures | None |
| Supported runtimes | New record/schema/comparison features | Explicit local result recording and ID/state snapshots | Schema compatibility, scope mismatch, invalid dates, malformed/bounded records, redaction, private writes | No new physical-device validation yet |

Python 3.11 is the CI runtime on Ubuntu/macOS/Windows runners. A runner OS label
is not a supported-device version claim. The existing Windows CI additionally
checks local PowerShell output shapes and temporary file ACLs. New tests run
against synthetic browser directories and aggregate records. A successful CI
run never certifies the runner or validates a user's browser/account.

See the READMEs for exact historical run claims. Historical validation does not
establish a new-feature run or blanket compatibility. Physical findings,
account identifiers, extension names/IDs, profile paths and screenshots remain
private. Add future device notes only after an actual execution and record its
source commit, OS/browser/Python versions and scope.

## Why a result can be unknown or unavailable

| Situation | State / handling |
| --- | --- |
| Password Checkup or effective extension review not completed | unknown; never pass |
| Invalid, future-dated, oversized or unreadable manual record | unavailable; generic reason, no raw data |
| Chrome registry policy values conflict | unknown; effective state must be checked in UI |
| Registry read failed or malformed enum | unavailable |
| Chrome registry policy absent | effective Safe Browsing unknown; absence is not disabled/protected |
| Browser root is redirected/inaccessible | unavailable per browser; no inferred clean result |
| Browser directories were not detected | unknown discovery result; does not establish browser absence |
| Profile/extension/version enumeration capped or manifest unreadable | unavailable metadata; partial findings still shown |
| Brave/Edge effective grants or publishers requested | automatic scope is only directory counts; manual UI review required |
| Firefox/Safari extension inventory requested | automatic scope is presence only; manual UI review required |
| OS command fails/returns unrecognized output or macOS firewall is sandboxed | unavailable, same individual OS check ID |
| Unsupported OS/network/browser adapter | unavailable; no macOS fallback on Linux |
| Old snapshot/schema or different scan scope | comparison fails rather than claiming improvement |
| Previously observed ID missing | not observed now, never automatically resolved |

Read [manual review and comparison](review-and-comparison.md) for state meanings,
retention, schema compatibility, limits and deletion.
