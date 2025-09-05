package secure

import (
	"fmt"
	"strings"
)

// CSP Directive Constants
const (
	Self              = "'self'"
	UnsafeEval        = "'unsafe-eval'"
	WASMUnsafeEval    = "'wasm-unsafe-eval'"
	UnsafeInline      = "'unsafe-inline'"
	UnsafeHashes      = "'unsafe-hashes'"
	InlineSpeculation = "'inline-speculation-rules'"
	StrictDynamic     = "'strict-dynamic'"
	ReportSample      = "'report-sample'"
	None              = "'none'"
)

type CSPDirectives struct {
	// Defines valid sources for web workers and nested browsing contexts loading using elements such as <frame> and <iframe>.
	ChildSrc []string `split_words:"true" desc:"defines valid sources for web workers and nested browsing contexts loading using elements such as <frame> and <iframe>."`

	// Restricts the URLs which can be loaded using script interfaces.
	ConnectSrc []string `split_words:"true" desc:"restricts the URLs which can be loaded using script interfaces."`

	// Serves as a fallback for the other fetch directives.
	DefaultSrc []string `split_words:"true" desc:"serves as a fallback for the other fetch directives."`

	// Specifies valid sources for nested browsing contexts loaded into <fencedframe> elements.
	FencedFrameSrc []string `split_words:"true" desc:"specifies valid sources for nested browsing contexts loaded into <fencedframe> elements."`

	// Specifies valid sources for fonts loaded using @font-face.
	FontSrc []string `split_words:"true" desc:"specifies valid sources for fonts loaded using @font-face."`

	// Specifies valid sources for nested browsing contexts loaded into elements such as <frame> and <iframe>.
	FrameSrc []string `split_words:"true" desc:"specifies valid sources for nested browsing contexts loaded into elements such as <frame> and <iframe>."`

	// Specifies valid sources of images and favicons.
	ImgSrc []string `split_words:"true" desc:"specifies valid sources of images and favicons."`

	// Specifies valid sources of application manifest files.
	ManifestSrc []string `split_words:"true" desc:"specifies valid sources of application manifest files."`

	// Specifies valid sources for loading media using the <audio>, <video> and <track> elements.
	MediaSrc []string `split_words:"true" desc:"specifies valid sources for loading media using the <audio>, <video> and <track> elements."`

	// Specifies valid sources for the <object> and <embed> elements.
	ObjectSrc []string `split_words:"true" desc:"specifies valid sources for the <object> and <embed> elements."`

	// Specifies valid sources to be prefetched or prerendered.
	PrefetchSrc []string `split_words:"true" desc:"specifies valid sources to be prefetched or prerendered."`

	// Specifies valid sources for JavaScript and WebAssembly resources.
	ScriptSrc []string `split_words:"true" desc:"specifies valid sources for JavaScript and WebAssembly resources."`

	// Specifies valid sources for JavaScript <script> elements.
	ScriptSrcElem []string `split_words:"true" desc:"specifies valid sources for JavaScript <script> elements."`

	// Specifies valid sources for JavaScript inline event handlers.
	ScriptSrcAttr []string `split_words:"true" desc:"specifies valid sources for JavaScript inline event handlers."`

	// Specifies valid sources for stylesheets.
	StyleSrc []string `split_words:"true" desc:"specifies valid sources for stylesheets."`

	// Specifies valid sources for stylesheets <style> elements and <link> elements with rel="stylesheet".
	StyleSrcElem []string `split_words:"true" desc:"specifies valid sources for stylesheets <style> elements and <link> elements with rel=\"stylesheet\"."`

	// Specifies valid sources for stylesheets inline style attributes.
	StyleSrcAttr []string `split_words:"true" desc:"specifies valid sources for stylesheets inline style attributes."`

	// Specifies valid sources for worker, shared worker, or service worker scripts.
	WorkerSrc []string `split_words:"true" desc:"specifies valid sources for worker, shared worker, or service worker scripts."`

	// Restricts the URLs which can be used in a document's <base> element.
	BaseURI []string `split_words:"true" desc:"restricts the URLs which can be used in a document's <base> element."`

	// Enables a sandbox for the requested resource similar to the <iframe> sandbox attribute.
	Sandbox []string `split_words:"true" desc:"enables a sandbox for the requested resource similar to the <iframe> sandbox attribute."`

	// Specifies valid sources for the <form> element's action attribute.
	FormAction []string `split_words:"true" desc:"specifies valid sources for the <form> element's action attribute."`

	// Specifies valid parents that may embed a page using <frame>, <iframe>, <object>, or <embed>.
	FrameAncestors []string `split_words:"true" desc:"specifies valid parents that may embed a page using <frame>, <iframe>, <object>, or <embed>."`

	// Provides the browser with a token identifying the reporting endpoint or group of endpoints to send CSP violation information to.
	ReportTo string `split_words:"true" desc:"provides the browser with a token identifying the reporting endpoint or group of endpoints to send CSP violation information to."`

	// Enforces Trusted Types at the DOM XSS injection sinks.
	RequireTrustedTypesFor []string `split_words:"true" desc:"enforces Trusted Types at the DOM XSS injection sinks."`

	// Used to specify an allowlist of Trusted Types policies.
	TrustedTypes []string `split_words:"true" desc:"used to specify an allowlist of Trusted Types policies."`

	// Instructs user agents to treat all of a site's insecure URLs (those served over HTTP) as though they have been replaced with secure URLs (those served over HTTPS).
	UpgradeInsecureRequests bool `split_words:"true" default:"false" desc:"instructs user agents to treat all of a site's insecure URLs (those served over HTTP) as though they have been replaced with secure URLs (those served over HTTPS)."`
}

// Directive name constants (not exported)
const (
	childSrc                = "child-src"
	connectSrc              = "connect-src"
	defaultSrc              = "default-src"
	fencedFrameSrc          = "fenced-frame-src"
	fontSrc                 = "font-src"
	frameSrc                = "frame-src"
	imgSrc                  = "img-src"
	manifestSrc             = "manifest-src"
	mediaSrc                = "media-src"
	objectSrc               = "object-src"
	prefetchSrc             = "prefetch-src"
	scriptSrc               = "script-src"
	scriptSrcElem           = "script-src-elem"
	scriptSrcAttr           = "script-src-attr"
	styleSrc                = "style-src"
	styleSrcElem            = "style-src-elem"
	styleSrcAttr            = "style-src-attr"
	workerSrc               = "worker-src"
	baseURI                 = "base-uri"
	sandbox                 = "sandbox"
	formAction              = "form-action"
	frameAncestors          = "frame-ancestors"
	reportTo                = "report-to"
	requireTrustedTypesFor  = "require-trusted-types-for"
	trustedTypes            = "trusted-types"
	upgradeInsecureRequests = "upgrade-insecure-requests"
)

// Orders directive names for consistent output for all []string directives.
var directivesOrdered = []string{
	childSrc,
	connectSrc,
	defaultSrc,
	fencedFrameSrc,
	fontSrc,
	frameSrc,
	imgSrc,
	manifestSrc,
	mediaSrc,
	objectSrc,
	prefetchSrc,
	scriptSrc,
	scriptSrcElem,
	scriptSrcAttr,
	styleSrc,
	styleSrcElem,
	styleSrcAttr,
	workerSrc,
	baseURI,
	sandbox,
	formAction,
	frameAncestors,
	requireTrustedTypesFor,
	trustedTypes,
}

func (c CSPDirectives) Directive() string {
	directives := [][]string{
		c.ChildSrc,
		c.ConnectSrc,
		c.DefaultSrc,
		c.FencedFrameSrc,
		c.FontSrc,
		c.FrameSrc,
		c.ImgSrc,
		c.ManifestSrc,
		c.MediaSrc,
		c.ObjectSrc,
		c.PrefetchSrc,
		c.ScriptSrc,
		c.ScriptSrcElem,
		c.ScriptSrcAttr,
		c.StyleSrc,
		c.StyleSrcElem,
		c.StyleSrcAttr,
		c.WorkerSrc,
		c.BaseURI,
		c.Sandbox,
		c.FormAction,
		c.FrameAncestors,
		c.RequireTrustedTypesFor,
		c.TrustedTypes,
	}

	sb := new(strings.Builder)

	first := true
	for i, values := range directives {
		if len(values) == 0 {
			continue
		}

		if !first {
			sb.WriteString("; ")
		}
		first = false

		sb.WriteString(directivesOrdered[i])
		sb.WriteString(" ")
		sb.WriteString(strings.Join(values, " "))
	}

	if c.UpgradeInsecureRequests {
		if !first {
			sb.WriteString("; ")
		}
		first = false
		sb.WriteString(upgradeInsecureRequests)
	}

	if c.ReportTo != "" {
		if !first {
			sb.WriteString("; ")
		}
		first = false
		fmt.Fprintf(sb, "%s %s", reportTo, c.ReportTo)
	}

	return sb.String()
}

func (c CSPDirectives) IsZero() bool {
	return c.Directive() == ""
}
