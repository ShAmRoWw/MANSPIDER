import re

from man_spider.filters import ScopeMatcher


def matcher(**kwargs):
    defaults = {
        "filename_filters": (),
        "extensions": (),
        "excluded_extensions": (),
        "content_active": False,
        "included_shares": (),
        "excluded_shares": (),
        "included_directories": (),
        "excluded_directories": (),
        "date_active": False,
        "or_logic": False,
    }
    defaults.update(kwargs)
    return ScopeMatcher(**defaults)


def test_values_inside_each_category_use_or():
    scope = matcher(
        filename_filters=(re.compile(".*password.*", re.I), re.compile(".*secret.*", re.I)),
        extensions=(".txt", ".log"),
    )

    assert scope.final_include(share=None, directory="", filename="secret.csv", content_match=False) is False
    assert scope.final_include(share=None, directory="", filename="secret.log", content_match=False) is True
    assert scope.final_include(share=None, directory="", filename="password.txt", content_match=False) is True


def test_default_and_and_explicit_or_between_categories():
    values = {
        "filename_filters": (re.compile(".*secret.*", re.I),),
        "extensions": (".txt",),
    }
    and_scope = matcher(**values)
    or_scope = matcher(**values, or_logic=True)

    assert and_scope.final_include(share=None, directory="", filename="secret.log") is False
    assert or_scope.final_include(share=None, directory="", filename="secret.log") is True


def test_content_remains_a_candidate_under_or_when_metadata_misses():
    scope = matcher(
        filename_filters=(re.compile(".*secret.*", re.I),),
        extensions=(".txt",),
        content_active=True,
        or_logic=True,
    )

    values = {"share": None, "directory": "ordinary", "filename": "ordinary.log", "date_match": True}
    assert scope.pre_content_candidate(**values) is True
    assert scope.final_include(**values, content_match=False) is False
    assert scope.final_include(**values, content_match=True) is True


def test_default_and_can_prefilter_before_content_read():
    scope = matcher(
        filename_filters=(re.compile(".*secret.*", re.I),),
        content_active=True,
    )

    assert scope.pre_content_candidate(share=None, directory="", filename="ordinary.txt", date_match=True) is False
    assert scope.pre_content_candidate(share=None, directory="", filename="secret.txt", date_match=True) is True


def test_exclusions_are_independent_of_include_logic():
    scope = matcher(
        extensions=(".txt",),
        excluded_extensions=(".txt",),
        excluded_shares=("admin$",),
        excluded_directories=("private",),
        or_logic=True,
    )

    assert scope.file_exclusion("secret.txt") is not None
    assert scope.share_exclusion("ADMIN$") is not None
    assert scope.directory_exclusion("parent/private/child") is not None


def test_non_file_share_type_is_excluded_even_without_name_filter():
    scope = matcher()
    assert scope.share_exclusion("IPC-custom", share_type=3) is not None
    assert scope.share_exclusion("files", share_type=0) is None
    assert "unknown SMB type" in scope.share_exclusion("unknown", share_type=None)


def test_directory_include_does_not_control_traversal():
    scope = matcher(included_directories=("matching-child",))

    assert scope.directory_matches("unmatched-parent") is False
    assert scope.directory_exclusion("unmatched-parent") is None
    assert scope.directory_matches("unmatched-parent/matching-child") is True


def test_unmatched_share_is_traversed_under_or_if_another_category_can_match():
    and_scope = matcher(included_shares=("finance",), extensions=(".txt",))
    or_scope = matcher(included_shares=("finance",), extensions=(".txt",), or_logic=True)

    assert and_scope.should_traverse_share("public") is False
    assert or_scope.should_traverse_share("public") is True
