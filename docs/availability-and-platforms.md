# Command Availability and Platform Awareness

CommandGraph can use local command availability and Linux distribution metadata as small, explainable search-ranking signals.

The feature remains local-first. It does not contact a package registry, operating-system service, or remote telemetry endpoint.

## Availability

For each search candidate, CommandGraph checks whether the executable can be resolved on the current `PATH` using the local equivalent of `which`.

Search-result JSON exposes:

- `available`: whether the executable was found;
- `executable_path`: the resolved path when available;
- `availability_reason`: a short explanation of availability/platform evidence.

Availability is deliberately a bounded ranking signal rather than a filter. A command that is not installed can still be returned when it best matches the requested intent, so CommandGraph can continue to serve discovery and installation workflows.

## Linux Distribution Detection

On Linux, CommandGraph reads `/etc/os-release` locally and uses the standard fields:

- `ID`
- `ID_LIKE`
- `VERSION_ID`

If the file is unavailable or does not identify a distribution, compatibility remains unknown rather than being guessed.

Other operating systems are represented by their normalized platform name. No remote platform lookup is performed.

## Command Card Platform Metadata

Command cards may add an optional `platforms` object:

```json
{
  "platforms": {
    "os": ["linux"],
    "distro_ids": ["debian", "ubuntu"],
    "distro_like": ["debian"]
  }
}
```

The fields are additive to `commandgraph.command_card.v1`:

- `os` lists supported normalized operating-system names;
- `distro_ids` lists explicit Linux distribution IDs;
- `distro_like` lists accepted Linux distribution families.

`apt` and `apt-get` are initially annotated as Debian-family commands.

## Ranking Policy

Intent relevance remains the dominant search signal. Availability/platform adjustments are intentionally small:

- locally available: small positive signal;
- unavailable: very small negative signal;
- explicitly platform-compatible: small positive signal;
- explicitly incompatible: bounded negative signal.

The combined adjustment is clamped so environment metadata cannot overwhelm a strong intent match.

Platform-incompatible commands are **not removed** from results. The result is annotated so callers can decide whether to install an alternative, use a distro-specific equivalent, or ignore the compatibility signal.

## Testing and Injection

The search API accepts optional injected `EnvironmentInfo` and executable-resolution functions. Tests use these injection points rather than depending on the CI runner's installed commands or distribution.

This keeps ranking tests deterministic and allows later retrieval work to measure availability signals against the checked-in search-quality benchmark.
