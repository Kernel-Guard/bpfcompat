package runtime

type ExecuteWorkerRequest struct {
	Execute ExecuteRequest `json:"execute"`
}

type ExecuteWorkerResponse struct {
	Execution ExecuteResult `json:"execution"`
}
