from commandgraph.availability import (
    EnvironmentInfo,
    command_availability,
    environment_from_os_release,
    parse_os_release,
    platform_compatibility,
)


def _apt_entry():
    return {
        "command": "apt",
        "platforms": {
            "os": ["linux"],
            "distro_ids": ["debian", "ubuntu", "linuxmint", "pop"],
            "distro_like": ["debian"],
        },
    }


def test_parse_os_release_handles_quotes_and_comments():
    payload = parse_os_release('# comment\nID="ubuntu"\nID_LIKE="debian"\nVERSION_ID="24.04"\n')

    assert payload == {
        "ID": "ubuntu",
        "ID_LIKE": "debian",
        "VERSION_ID": "24.04",
    }


def test_environment_from_os_release_normalizes_linux_distribution():
    environment = environment_from_os_release(
        "linux",
        'ID="ubuntu"\nID_LIKE="debian"\nVERSION_ID="24.04"\n',
    )

    assert environment.os == "linux"
    assert environment.distro_id == "ubuntu"
    assert environment.distro_like == ("debian",)
    assert environment.version_id == "24.04"


def test_apt_matches_debian_family_distribution():
    compatible, reason = platform_compatibility(
        _apt_entry(),
        EnvironmentInfo(os="linux", distro_id="ubuntu", distro_like=("debian",)),
    )

    assert compatible is True
    assert "matches ubuntu" in reason


def test_apt_is_incompatible_with_fedora_family():
    compatible, reason = platform_compatibility(
        _apt_entry(),
        EnvironmentInfo(os="linux", distro_id="fedora", distro_like=("rhel",)),
    )

    assert compatible is False
    assert "fedora" in reason


def test_unknown_linux_distribution_keeps_platform_status_unknown():
    compatible, reason = platform_compatibility(
        _apt_entry(),
        EnvironmentInfo(os="linux"),
    )

    assert compatible is None
    assert reason == "Linux distribution could not be identified"


def test_command_availability_uses_injected_path_resolver():
    availability = command_availability(
        _apt_entry(),
        environment=EnvironmentInfo(os="linux", distro_id="ubuntu"),
        which=lambda command: "/usr/bin/apt" if command == "apt" else None,
    )

    assert availability.installed is True
    assert availability.executable_path == "/usr/bin/apt"
    assert availability.platform_compatible is True
    assert availability.score_adjustment == 0.8


def test_incompatible_missing_command_penalty_is_bounded():
    availability = command_availability(
        _apt_entry(),
        environment=EnvironmentInfo(os="darwin"),
        which=lambda command: None,
    )

    assert availability.installed is False
    assert availability.platform_compatible is False
    assert availability.score_adjustment == -0.7
