/* ************************************************************** */
/*                                                                */
/* IBM Confidential                                               */
/*                                                                */
/* OCO Source Materials                                           */
/*                                                                */
/* 5737-L66                                                       */
/*                                                                */
/* (C) Copyright IBM Corp. 2019, 2024                             */
/*                                                                */
/* The source code for this program is not published or otherwise */
/* divested of its trade secrets, irrespective of what has been   */
/* deposited with the U.S. Copyright Office.                      */
/*                                                                */
/* ************************************************************** */

/*******************************************************************************
 * NAME: tenant.go
 * DESCRIPTION: A helper used as an service between api and mongo db connection.
 * AUTHOR: Sohel Almozaini (sohel@ibm.com)
 *******************************************************************************/

// helper/ddr-rule-engine.go
package helper

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/open-policy-agent/opa/rego"
)

type Range struct {
	Min       float64
	Max       float64
	IsBoolean bool
}

type Condition struct {
	AnyOf map[string]Range
}

var (
	rulesMap         map[string]Condition
	dbUserPrepared   []rego.PreparedEvalQuery
	databasePrepared []rego.PreparedEvalQuery
	osuserPrepared   []rego.PreparedEvalQuery
	onceDbUser       sync.Once
	onceDatabase     sync.Once
	onceOSUser       sync.Once
)

func InitDbUserRegoInstance(dbUserPolicyPath string) {
	onceDbUser.Do(func() {
		dbUserPolicyData, err := os.ReadFile(dbUserPolicyPath)
		if err != nil {
			log.Fatalf("Error reading dbuser policy file: %v", err)
		}
		queries := []string{
			"data.policies.dbuser.excessive_data_act",

			//"data.policies.dbuser.severity2",
			//"data.policies.dbuser.severity3",
			//"data.policies.dbuser.severity4",
			//"data.policies.dbuser.severity5",
			//"data.policies.dbuser.severity6",
		}

		for _, query := range queries {
			dbUserRego := rego.New(
				rego.Query(query),
				rego.Module("policies/dbuser_policy.rego", string(dbUserPolicyData)),
			)
			preparedQuery, err := dbUserRego.PrepareForEval(context.Background())
			if err != nil {
				log.Fatalf("Error preparing dbuser policy for evaluation: %v", err)
			}
			dbUserPrepared = append(dbUserPrepared, preparedQuery)
		}
	})
}

func InitDatabaseRegoInstance(databasePolicyPath string) {
	onceDatabase.Do(func() {
		databasePolicyData, err := os.ReadFile(databasePolicyPath)
		if err != nil {
			log.Fatalf("Error reading database policy file: %v", err)
		}
		queries := []string{
			"data.policies.database.severity1",
			"data.policies.database.severity2",
			"data.policies.database.severity3",
			"data.policies.database.severity4",
			"data.policies.database.severity5",
			"data.policies.database.severity6",
		}

		for _, query := range queries {
			databaseRego := rego.New(
				rego.Query(query),
				rego.Module("policies/database_policy.rego", string(databasePolicyData)),
			)
			preparedQuery, err := databaseRego.PrepareForEval(context.Background())
			if err != nil {
				log.Fatalf("Error preparing database policy for evaluation: %v", err)
			}
			databasePrepared = append(databasePrepared, preparedQuery)
		}
	})
}

func InitOsuserRegoInstance(osuserPolicyPath string) {
	onceOSUser.Do(func() {
		osuserPolicyData, err := os.ReadFile(osuserPolicyPath)
		if err != nil {
			log.Fatalf("Error reading database policy file: %v", err)
		}
		queries := []string{
			"data.policies.osuser.severity1",
			"data.policies.osuser.severity2",
			"data.policies.osuser.severity3",
			"data.policies.osuser.severity4",
			"data.policies.osuser.severity5",
			"data.policies.osuser.severity6",
		}

		for _, query := range queries {
			osuserRego := rego.New(
				rego.Query(query),
				rego.Module("policies/osuser_policy.rego", string(osuserPolicyData)),
			)
			preparedQuery, err := osuserRego.PrepareForEval(context.Background())
			if err != nil {
				log.Fatalf("Error preparing osuser policy for evaluation: %v", err)
			}
			osuserPrepared = append(osuserPrepared, preparedQuery)
		}
	})
}

// RuleExecution function processes the input and evaluates the Rego policy.
func RuleExecution(input map[string]interface{}) (string, []string) {
	ctx := context.Background()
	pivotPrepared := dbUserPrepared // Modify as needed

	// Iterate over each prepared query to evaluate policies.
	for _, preparedQuery := range pivotPrepared {
		// Evaluate once per query and handle results efficiently
		results, err := preparedQuery.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			log.Fatalf("Error evaluating dbuser policy: %v", err)
		}

		// Process all results from the evaluation
		for _, result := range results {

			//fmt.Printf("Result: %+v\n", result) // This will print each result

			if len(result.Expressions) > 0 {
				// Extract severity and features without unnecessary conversions
				severity, matchedFeatures := extractSeverityAndFeatures(result.Expressions[0].Value, input)
				if severity != "NO MATCH" {
					// If you find a match, return immediately
					return severity, matchedFeatures
				}
			}
		}
	}

	// Return "NO MATCH" if no match was found
	return "NO MATCH", nil
}

func extractSeverityAndFeatures(result interface{}, input map[string]interface{}) (string, []string) {
	// Ensure the result is a slice of maps (as we expect only one match).
	if resultSlice, ok := result.([]interface{}); ok && len(resultSlice) > 0 {
		// Extract the first element (map) in the slice
		if output, ok := resultSlice[0].(map[string]interface{}); ok {
			// Extract rule_id and severity only if both exist
			if ruleID, ruleIDOk := output["rule_id"].(string); ruleIDOk {
				if severity, severityOk := output["severity"].(string); severityOk {
					// Directly return the severity and matched features (no further computation needed here)
					matchedFeatures := evaluateSeverity(input, ruleID)
					return severity, matchedFeatures
				}
			}
		}
	}

	// If we can't extract necessary fields, return "NO MATCH"
	return "NO MATCH", nil
}

func evaluateSeverity(input map[string]interface{}, ruleID string) []string {
	condition, exists := rulesMap[ruleID]
	if !exists {
		return nil
	}

	var matchedFeatures []string
	for feature, rangeLimit := range condition.AnyOf {
		val, exists := input[feature].(float64)
		if exists {
			if isInRange(val, rangeLimit) {
				matchedFeatures = append(matchedFeatures, feature)
			}
		}
	}
	return matchedFeatures
}

func isInRange(value float64, rangeLimit Range) bool {
	if rangeLimit.IsBoolean {
		return value == 1
	}
	match := value >= rangeLimit.Min && value <= rangeLimit.Max
	//log.Printf("Value %f in range [%f, %f]: %v", value, rangeLimit.Min, rangeLimit.Max, match)
	return match
}

func LoadRules(filePath string) {
	rulesData, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Error reading rules file: %v", err)
	}

	var rules map[string]Condition
	err = json.Unmarshal(rulesData, &rules)
	if err != nil {
		log.Fatalf("Error unmarshaling rules data: %v", err)
	}
	rulesMap = rules

}
