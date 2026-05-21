# CrowdStrike Spotlight Integration

A Starlark-based integration that pulls assets and vulnerabilities from CrowdStrike Falcon into Zafran's Threat Exposure Management platform.

## What It Does

- Authenticates with CrowdStrike's OAuth2 API
- Fetches all host/device assets via the Hosts API
- Fetches open vulnerabilities via the Spotlight API
- Maps devices to Zafran's `InstanceData` model
- Maps vulnerabilities to Zafran's `Vulnerability` model

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `api_url` | CrowdStrike API base URL | `https://api.crowdstrike.com` |
| `api_key` | OAuth2 Client ID | (required) |
| `api_secret` | OAuth2 Client Secret | (required) |
| `page_size` | Number of items per page | `100` |

## Required CrowdStrike API Scopes

The API client must have the following permissions:

- **Hosts**: Read
- **Spotlight Vulnerabilities**: Read

## Usage

```bash
./starlark-runner-mac -script crowdstrike-integration/main.star -params "api_url=https://api.crowdstrike.com,api_key=YOUR_CLIENT_ID,api_secret=YOUR_CLIENT_SECRET"
```

## CrowdStrike API Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `POST /oauth2/token` | OAuth2 authentication |
| `GET /devices/queries/devices-scroll/v1` | Paginate all device IDs |
| `GET /devices/entities/devices/v2` | Fetch full device details |
| `GET /spotlight/combined/vulnerabilities/v1` | Fetch vulnerabilities with CVE and remediation data |

## Data Mapping

### Device → InstanceData

| CrowdStrike Field | Zafran Field |
|-------------------|--------------|
| `device_id` | `instance_id` |
| `hostname` | `name` |
| `platform_name` + `os_version` | `operating_system` |
| `local_ip`, `external_ip` | `asset_information.ip_addresses` |
| `mac_address` | `asset_information.mac_addresses` |
| `device_id` | `identifiers` (as `CROWDSTRIKE_AID`) |
| `tags` | `key_value_tags` |
| `product_type_desc`, `platform_name` | `labels` |

### Vulnerability → Vulnerability

| CrowdStrike Field | Zafran Field |
|-------------------|--------------|
| `aid` | `instance_id` |
| `cve.id` | `cve` |
| `cve.description` | `description` |
| `cve.severity` | `severity` |
| `cve.base_score` + `cve.vector` | `CVSS` |
| `apps[0]` (product, vendor, version) | `component` |
| `remediation.action` | `remediation.suggestion` |

## Architecture

The integration runs in two phases:

1. **Instances** — Scroll all device IDs, batch-fetch details, map to `InstanceData`, flush
2. **Vulnerabilities** — Paginate Spotlight combined endpoint, map to `Vulnerability`, flush

Instances are flushed before vulnerabilities to ensure the link between them is preserved.