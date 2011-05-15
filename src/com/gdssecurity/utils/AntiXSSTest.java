package com.gdssecurity.utils;

import junit.framework.TestCase;

public class AntiXSSTest extends TestCase {

	public void testHtmlAttributeEncode() {
        assertEquals("", AntiXSS.HtmlAttributeEncode(""));
        assertEquals("&#60;script&#62;&#32;", AntiXSS.HtmlAttributeEncode("<script> "));
        assertEquals("&#60;script&#62;.", AntiXSS.HtmlAttributeEncode("\u003cscript\u003e."));
        assertEquals("&#38;amp&#59;script&#38;amp&#59;", AntiXSS.HtmlAttributeEncode("&amp;script&amp;"));
	}

	public void testHtmlEncode() {
        assertEquals("", AntiXSS.HtmlEncode(""));
        assertEquals("&#60;script&#62; ", AntiXSS.HtmlEncode("<script> "));
        assertEquals("&#60;script&#62;.", AntiXSS.HtmlEncode("\u003cscript\u003e."));
        assertEquals("&#38;amp&#59;script&#38;amp&#59;", AntiXSS.HtmlEncode("&amp;script&amp;"));
	}

	public void testJavaScriptEncode() {
        assertEquals("'eval\\x28\\x27\\x3b'", AntiXSS.JavaScriptEncode("eval(';"));
        assertEquals("'eval\\u0080'", AntiXSS.JavaScriptEncode("eval\u0080"));
        assertEquals("'\\x3cscript\\x3e.'", AntiXSS.JavaScriptEncode("\u003cscript\u003e."));
	}

	public void testUrlEncode() {
        assertEquals("", AntiXSS.UrlEncode(""));
        assertEquals("http%3a%2f%2fwww.google.com", AntiXSS.UrlEncode("http://www.google.com"));
        assertEquals("http%3a%2f%2fwww.google.com%3fgoogle%3dblah%27", AntiXSS.UrlEncode("http://www.google.com?google=blah'"));
        assertEquals("http%3a%2f%2fwww.google.com%u0177", AntiXSS.UrlEncode("http://www.google.com\u0177"));
	}

	public void testVisualBasicScriptEncodeString() {
        assertEquals("chrw(33)&chrw(64)&chrw(163)", AntiXSS.VisualBasicScriptEncodeString("!@£"));
        assertEquals("\"foo\"&chrw(58)&chrw(39)&\"foo\"", AntiXSS.VisualBasicScriptEncodeString("foo:'foo"));
	}

	public void testXmlAttributeEncode() {
        assertEquals("", AntiXSS.XmlAttributeEncode(""));
        assertEquals("&#60;script&#62;&#32;", AntiXSS.XmlAttributeEncode("<script> "));
        assertEquals("&#60;script&#62;.", AntiXSS.XmlAttributeEncode("\u003cscript\u003e."));
	}

	public void testXmlEncode() {
        assertEquals("", AntiXSS.XmlEncode(""));
        assertEquals("&#60;script&#62; ", AntiXSS.XmlEncode("<script> "));
        assertEquals("&#60;script&#62;.", AntiXSS.XmlEncode("\u003cscript\u003e."));
        assertEquals("&#38;amp&#59;script&#38;amp&#59;", AntiXSS.XmlEncode("&amp;script&amp;"));
	}
}
