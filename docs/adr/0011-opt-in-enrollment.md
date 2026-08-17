# A Target joins the inventory by opt-in Enrollment

An Operator or repo admin enrolls a repo or image repo. The first successful Scan of the default Revision writes the Baseline and does not fail. The Gate starts on later PRs. We rejected auto-enrolling every org repo (surprise Gates) and workflow-file-as-the-only-opt-in (HQ could not re-scan when intel changes).
