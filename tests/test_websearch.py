"""Pruebas de búsqueda web y enlaces directos a perfiles."""

from __future__ import annotations

import base64
import unittest
from unittest import mock

from osintkit.modules import email as email_module
from osintkit.modules import phone as phone_module
from osintkit.modules import websearch
from osintkit.modules.websearch import SearchHit


class WebsearchTests(unittest.TestCase):
    def test_search_pages_are_rejected(self) -> None:
        self.assertTrue(websearch.is_search_page("https://www.google.com/search?q=foo"))
        self.assertTrue(websearch.is_search_page("https://duckduckgo.com/?q=foo"))
        self.assertTrue(websearch.is_search_page("https://github.com/search?q=foo"))
        self.assertTrue(websearch.is_search_page("https://www.facebook.com/search/top?q=foo"))
        self.assertFalse(websearch.is_search_page("https://github.com/foo"))

    def test_profile_urls_are_direct(self) -> None:
        self.assertTrue(websearch.is_profile_url("https://github.com/foo"))
        self.assertTrue(websearch.is_profile_url("https://m.facebook.com/foo"))
        self.assertTrue(websearch.is_profile_url("https://www.linkedin.com/in/foo"))
        self.assertTrue(websearch.is_profile_url("https://wa.me/34600123456"))
        self.assertFalse(websearch.is_profile_url("https://github.com/search?q=foo"))
        self.assertFalse(websearch.is_profile_url("https://www.google.com/search?q=foo"))

    def test_profile_label(self) -> None:
        self.assertEqual(websearch.profile_label("https://github.com/foo"), "GitHub")
        self.assertEqual(websearch.profile_label("https://gist.github.com/foo"), "GitHub Gist")
        self.assertEqual(websearch.profile_label("https://x.com/foo"), "X/Twitter")
        self.assertEqual(websearch.profile_label("https://wa.me/34600123456"), "WhatsApp")

    def test_parse_duckduckgo_result_url(self) -> None:
        html = (
            '<a class="result__a" href="//duckduckgo.com/l/?uddg='
            'https%3A%2F%2Fgithub.com%2Ffoo&amp;rut=abc">Perfil GitHub</a>'
        )
        hits = websearch._parse_ddg(html, "DuckDuckGo", '"foo" site:github.com')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].url, "https://github.com/foo")
        self.assertEqual(hits[0].title, "Perfil GitHub")
        self.assertEqual(hits[0].query, '"foo" site:github.com')

    def test_parse_bing_decodes_redirect(self) -> None:
        target = "https://github.com/foo"
        encoded = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
        html = (
            '<li class="b_algo"><h2><a href="https://www.bing.com/ck/a?u=a1'
            + encoded
            + '&ntb=1">Perfil</a></h2><p>foo</p></li>'
        )
        hits = websearch._parse_bing(html, '"foo" site:github.com')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].url, target)
        self.assertEqual(hits[0].engine, "Bing")

    def test_resolve_direct_filters_search_and_irrelevant(self) -> None:
        fake_hits = [
            SearchHit("Buscador", "https://www.google.com/search?q=foo", "", "DuckDuckGo"),
            SearchHit("Perfil", "https://github.com/foo", "foo", "DuckDuckGo"),
            SearchHit("Perfil ajeno", "https://github.com/bar", "bar", "DuckDuckGo"),
            SearchHit("Otro", "https://example.com/bar", "bar", "DuckDuckGo"),
        ]
        with mock.patch.object(websearch, "duckduckgo", return_value=fake_hits):
            hits = websearch.resolve_direct(None, ["foo"], terms=["foo"])
        self.assertEqual([hit.url for hit in hits], ["https://github.com/foo"])


class EmailPhoneDirectLinkTests(unittest.TestCase):
    def test_email_returns_direct_profile(self) -> None:
        hit = SearchHit("Perfil", "https://github.com/foo", "foo@example.com", "DuckDuckGo")
        ctx = mock.Mock(target="foo@example.com", kind="email")
        with mock.patch.object(email_module, "_github_email_profiles", return_value=[]), \
                mock.patch.object(email_module, "resolve_direct", return_value=[hit]):
            findings = email_module.email_dork(ctx, None)
        self.assertEqual(findings[0].title, "Perfiles directos")
        self.assertEqual(findings[1].url, "https://github.com/foo")
        self.assertEqual(findings[1].level, "good")
        self.assertTrue(findings[1].data.get("email_page"))
        self.assertTrue(findings[1].data.get("email_exact"))

    def test_email_fallback_is_labeled(self) -> None:
        ctx = mock.Mock(target="foo@example.com", kind="email")
        with mock.patch.object(email_module, "_github_email_profiles", return_value=[]), \
                mock.patch.object(email_module, "resolve_direct", return_value=[]):
            findings = email_module.email_dork(ctx, None)
        self.assertEqual(findings[1].title, "Búsqueda manual")
        self.assertIn("duckduckgo.com", findings[1].url)
        self.assertNotIn("google.com/search", findings[1].url)

    def test_github_email_profiles(self) -> None:
        users = mock.Mock()
        users.ok = True
        users.json.return_value = {"items": [{"login": "foo", "html_url": "https://github.com/foo"}]}
        commits = mock.Mock()
        commits.ok = True
        commits.json.return_value = {
            "items": [{"author": {"login": "bar", "html_url": "https://github.com/bar"}}]
        }
        ctx = mock.Mock()
        ctx.http.get.side_effect = [users, commits]
        findings = email_module._github_email_profiles(ctx, "foo@example.com")
        self.assertEqual([item.url for item in findings], ["https://github.com/foo", "https://github.com/bar"])
        self.assertTrue(all(item.data.get("email_exact") for item in findings))

    def test_phone_returns_direct_profile(self) -> None:
        hit = SearchHit("Perfil", "https://wa.me/34600123456", "34600123456", "DuckDuckGo")
        ctx = mock.Mock(target="+34 600 123 456", kind="phone")
        with mock.patch.object(phone_module, "resolve_direct", return_value=[hit]):
            findings = phone_module.phone_dork(ctx, None)
        self.assertEqual(findings[0].title, "Perfiles directos")
        self.assertEqual(findings[1].url, "https://wa.me/34600123456")
        self.assertEqual(findings[1].level, "good")

    def test_phone_fallback_is_labeled(self) -> None:
        ctx = mock.Mock(target="+34 600 123 456", kind="phone")
        with mock.patch.object(phone_module, "resolve_direct", return_value=[]):
            findings = phone_module.phone_dork(ctx, None)
        by_title = {item.title: item for item in findings}
        self.assertIn("WhatsApp · contacto directo", by_title)
        self.assertEqual(by_title["WhatsApp · contacto directo"].url, "https://wa.me/34600123456")
        self.assertTrue(by_title["WhatsApp · contacto directo"].data.get("contact_link"))
        self.assertIn("Búsqueda manual", by_title)
        self.assertIn("duckduckgo.com", by_title["Búsqueda manual"].url)

    def test_phone_variants_expand_international_formats(self) -> None:
        variants = phone_module._phone_variants("+34 600 123 456")
        self.assertIn("+34600123456", variants)
        self.assertIn("600123456", variants)
        self.assertIn("600 123 456", variants)
        self.assertEqual(phone_module._phone_variants("600123456"), ["600123456"])

    def test_phone_dork_uses_all_variants_and_more_results(self) -> None:
        ctx = mock.Mock(target="+34 600 123 456", kind="phone")
        with mock.patch.object(phone_module, "resolve_direct", return_value=[]) as search:
            phone_module.phone_dork(ctx, None)
        queries = search.call_args.args[1]
        kwargs = search.call_args.kwargs
        self.assertTrue(any("600 123 456" in query for query in queries))
        self.assertIn("600 123 456", kwargs["terms"])
        self.assertEqual(kwargs["limit"], 50)

    def test_phone_sources_are_marked_as_directories(self) -> None:
        ctx = mock.Mock(target="+34 600 123 456", kind="phone")
        findings = phone_module.phone_sources(ctx, None)
        links = [item for item in findings if item.url]
        self.assertTrue(links)
        self.assertTrue(all(item.data.get("source_directory") for item in links))

    def test_email_dork_adds_general_and_document_queries(self) -> None:
        ctx = mock.Mock(target="foo@example.com", kind="email")
        with mock.patch.object(email_module, "_github_email_profiles", return_value=[]), \
                mock.patch.object(email_module, "resolve_direct", return_value=[]) as search:
            email_module.email_dork(ctx, None)
        queries = search.call_args.args[1]
        kwargs = search.call_args.kwargs
        self.assertIn('"foo@example.com"', queries)
        self.assertTrue(any("filetype:pdf" in query for query in queries))
        self.assertEqual(kwargs["limit"], 60)


if __name__ == "__main__":
    unittest.main()
