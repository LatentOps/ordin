from ordin.search import search


def test_runnable_query_finds_chmod_first():
    results = search("make file runnable", limit=3)
    assert results
    assert results[0].command == "chmod"
    assert results[0].as_dict()["schema_version"] == "ordin.search_result.v1"


def test_port_query_finds_inspection_tools():
    results = search("what is using port 3000", limit=3)
    commands = [result.command for result in results]
    assert "lsof" in commands
    assert "ss" in commands
    lsof = next(result for result in results if result.command == "lsof")
    assert lsof.suggested_commands[0]["command"] == "lsof -i :3000"


def test_disk_usage_query_finds_du():
    results = search("show biggest folders", limit=1)
    assert results[0].command == "du"


def test_find_named_query_suggests_find_template():
    results = search('find files named "*.py" in ./src', limit=1)
    assert results[0].command == "find"
    assert results[0].suggested_commands[0]["command"] == 'find ./src -name "*.py"'


def test_package_query_finds_package_managers():
    commands = [result.command for result in search("install package requests", limit=5)]
    assert "pip" in commands
    assert "npm" in commands


def test_dns_query_finds_dig():
    results = search("lookup dns for domain example.com", limit=1)
    assert results[0].command == "dig"
