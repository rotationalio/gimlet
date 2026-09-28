package csrf

// TODO: http request type below; for now it's like pseudo-code
func TODOCheck(request any) error {
	// TODO: implement these checks in order; return early when a policy decides:
	//
	// 1. Read Sec-Fetch-Site and the other Sec-Fetch headers. If Mode, Dest, or
	//    User is present, inspect it only when that check is configured. If one is
	//    absent, skip it unless the user explicitly requires it. Never use
	//    User-Agent to decide whether a request came from a browser.
	//
	// 2. For safe methods (GET, HEAD, OPTIONS), allow by default. Application
	//    handlers must never change state on these methods. TRACE is not considered
	//    safe here.
	//
	// 3. For a state-changing method with no Sec-Fetch-Site, first run the optional
	//    fallback predicate (for example, to allow a request already authenticated
	//    with a non-cookie credential). Otherwise, validate Origin, then Referer,
	//    against configured exact origins. If neither proves an allowed origin,
	//    reject by default. Only WithAllowMissingMetadata(true) should make this
	//    fail open. Missing headers can mean an old browser or a proxy stripped
	//    them, not just curl.
	//
	// 4. For a present Sec-Fetch-Site value, switch on its exact value:
	//    - "same-origin": allow; this does not protect against XSS on this origin.
	//    - "same-site": allow only when Origin exactly matches WithAllowSameSite's
	//      approved origins. Require scheme, host, and port; reject missing, "null",
	//      malformed, or unapproved origins. No wildcards or suffix matching.
	//    - "cross-site": reject state-changing requests, regardless of Origin.
	//    - "none": reject state-changing requests by default; allow only when
	//      explicitly configured.
	//    - unknown value: use the same fallback checks as missing metadata, then
	//      reject by default. Only WithAllowUnknownSite(true) should fail open.
	//
	// 5. Do not let Mode, Dest, or User override a cross-site write rejection.
	//    "navigate"/"document" can describe a cross-site form POST too; they are
	//    context hints, not proof that a state-changing request is safe.
	//
	// 6. On rejection, preserve Gimlet's CSRF status, response body, and stable
	//    error signal. Set the error header derived from the configured namespace.
	//    Treat every approved same-site origin as trusted to make authenticated
	//    writes; a compromised or XSS-vulnerable approved origin can bypass CSRF
	//    protection.

	return nil // TODO: reaching this point means the request is allowed; reject explicitly above? otherwise reject at the end and exit early when an "allow" stat is reached
}

// TODO: options to expose from the secfetch csrf package:
//   - WithNamespace(ns string): namespace the CSRF error header, e.g. X-Namespace-CSRF-Error.
//   - WithExpectedOrigins(origins []string): exact origins accepted by the Origin/Referer fallback; default empty.
//   - WithAllowSameSite(origins []string): allow same-site writes only from these exact origins; default empty.
//   - WithFallback(check func(*gin.Context) bool): optional verified-auth check for missing/unknown metadata; default none.
//   - WithAllowMissingMetadata(allow bool): allow unverified state-changing requests with no Fetch Metadata; default false.
//   - WithAllowUnknownSite(allow bool): allow an unrecognized Sec-Fetch-Site value without fallback validation; default false.
//   - WithAllowSiteNone(allow bool): allow state-changing requests with Sec-Fetch-Site: none; default false.
//   - WithAllowedFetchModes(modes []string): restrict Sec-Fetch-Mode when present; no restriction by default.
//   - WithAllowedFetchDestinations(destinations []string): restrict Sec-Fetch-Dest when present; no restriction by default.
//   - WithRequireFetchMode(require bool): reject state-changing requests if Sec-Fetch-Mode is missing; default false.
//   - WithRequireFetchDestination(require bool): reject state-changing requests if Sec-Fetch-Dest is missing; default false.
//
// The fallback check runs after authentication middleware. It must confirm that a
// non-cookie credential was successfully authenticated, not merely that a header
// or credential was supplied. If it returns false, continue with Origin/Referer
// validation and reject if no configured policy allows the request.
