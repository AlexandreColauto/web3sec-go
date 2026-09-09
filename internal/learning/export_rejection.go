package learning

// RejectionClassForStatus is _REJECTION_CLASS_BY_STATUS.get(status): the
// three-way rejection class a negative-memory row's status derives, or ""
// when the status has no class. Exported for roles._known_non_issues.
func RejectionClassForStatus(status string) string {
	return rejectionClassByStatus[status]
}
