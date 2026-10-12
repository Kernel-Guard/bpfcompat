package conformance

func buildTestResultStatement(decision Decision) Statement {
	result := "WARNED"
	switch decision.Status {
	case StatusConformant:
		result = "PASSED"
	case StatusNonconformant:
		result = "FAILED"
	}

	predicate := TestResultPredicate{
		Result: result,
		Configuration: []ResourceDescriptor{
			resourceFromEvaluation(decision.Profile),
			resourceFromEvaluation(decision.Matrix),
		},
		URL: decision.Report.URL,
	}
	for _, assertion := range decision.Assertions {
		switch assertion.Status {
		case AssertionPass:
			predicate.PassedTests = append(predicate.PassedTests, assertion.ID)
		case AssertionFail:
			predicate.FailedTests = append(predicate.FailedTests, assertion.ID)
		case AssertionInconclusive:
			predicate.WarnedTests = append(predicate.WarnedTests, assertion.ID)
		}
	}
	return Statement{
		Type:          StatementTypeV1,
		Subject:       []ResourceDescriptor{decision.Subject},
		PredicateType: TestResultPredicateTypeV01,
		Predicate:     predicate,
	}
}

func buildVerificationResultStatement(decision Decision) Statement {
	return Statement{
		Type:          StatementTypeV1,
		Subject:       []ResourceDescriptor{decision.Subject},
		PredicateType: SVRPredicateTypeV02,
		Predicate: SVRPredicate{
			Verifier: SVRVerifier{
				ID: decision.Verifier.ID,
				Policies: []ResourceDescriptor{
					resourceFromEvaluation(decision.Profile),
					resourceFromEvaluation(decision.Matrix),
				},
			},
			TimeCreated: decision.TimeCreated,
			Properties:  append([]string(nil), decision.Properties...),
		},
	}
}

func resourceFromEvaluation(resource EvaluatedResource) ResourceDescriptor {
	return ResourceDescriptor{
		Name: resource.ID,
		URI:  resource.URI,
		Digest: map[string]string{
			"sha256": resource.SHA256,
		},
	}
}
