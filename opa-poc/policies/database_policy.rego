package policies.database

import rego.v1

#1 ------------------- Excessive Data Activities Performed by the Privileged user --------------------------
# Rule ID and Severity mappings
severity1 = {"rule_id": "database_excessive_data_activities_critical", "severity": "CRITICAL1"} if {
    database_critical_condition
}
else := {"rule_id": "database_excessive_data_activities_high", "severity": "HIGH1"} if {
    database_high_condition
}
# Rule ID and Severity mappings
else :=  {"rule_id": "database_excessive_data_activities_medium", "severity": "MEDIUM1"} if {
    database_medium_condition
}
else :=  {"rule_id": "database_excessive_data_activities_low", "severity": "LOW1"} if {
    database_low_condition
}
# Critical Condition: Check for the critical severity rules
database_critical_condition if {
    input.database_is_high_volume_select_hour == 1
    input.database_is_high_volume_select_day == 1
    input.database_outlier_max_score_summary_hour >= 0.9
    input.database_is_admin_hour == 1
    input.database_sensitive_obj_hour >= 0.9
    input.database_sensitive_obj_day >= 0.8
}
# High Condition: Check for the high severity rules
database_high_condition if{
    input.database_is_high_volume_select_hour == 1
    input.database_is_high_volume_select_day == 1
    input.database_outlier_max_score_summary_hour >= 0.8
    input.database_outlier_max_score_summary_hour < 0.9
    input.database_is_admin_hour == 1
    input.database_sensitive_obj_hour >= 0.8
    input.database_sensitive_obj_hour < 0.9
    input.database_sensitive_obj_day >= 0.6
    input.database_sensitive_obj_day < 0.8
}
# Medium Condition: Check for the medium severity rules
database_medium_condition if{
    database_medium_high_volume_select_condition_or_outlier
    database_medium_admin_hour_condition
    database_medium_sensitive_obj_hour_condition
    database_medium_sensitive_obj_day_condition
}
# Low Condition: Check for the low severity rules
database_low_condition if {
    database_low_high_volume_select_condition_or_outlier
    input.database_is_admin_hour == 1
    input.database_sensitive_obj_hour >= 0.3
    input.database_sensitive_obj_hour < 0.6
    input.database_sensitive_obj_day < 0.3
}
#  Medium Helper Rules
# This condition allows for either high volume select OR outlier condition to pass for medium severity.
database_medium_high_volume_select_condition_or_outlier if{
    database_some_condition_is_true
}
database_some_condition_is_true if{
    database_is_high_volume_select_for_medium
}
database_some_condition_is_true if{
    database_is_outlier_max_score_for_medium
}
database_is_high_volume_select_for_medium if{
    input.database_is_high_volume_select_hour == 1
    input.database_is_high_volume_select_day == 1
}
database_is_outlier_max_score_for_medium if{
    input.database_outlier_max_score_summary_hour >= 0.6
    input.database_outlier_max_score_summary_hour < 0.8
}
database_medium_admin_hour_condition if{
    input.database_is_admin_hour == 1
}
database_medium_sensitive_obj_hour_condition if{
    input.database_sensitive_obj_hour >= 0.6
    input.database_sensitive_obj_hour < 0.8
}
database_medium_sensitive_obj_day_condition if{
    input.database_sensitive_obj_day >= 0.3
    input.database_sensitive_obj_day < 0.6
}
#  Low Helper Rules
database_low_high_volume_select_condition_or_outlier if {
    database_some_low_condition_is_true
}
database_some_low_condition_is_true if {
    input.database_is_high_volume_select_hour == 1
    input.database_is_high_volume_select_day == 1
}
database_some_low_condition_is_true if {
     input.database_outlier_max_score_summary_hour >= 0.3
     input.database_outlier_max_score_summary_hour < 0.6
}
#2 ------------------- Suspicious activities Performed on Sensitive Data --------------------------
# Rule ID and Severity mappings
severity2 = {"rule_id": "database_suspicious_activities_critical", "severity": "CRITICAL2"} if {
 database_is_valid_connection_critical(input.database_is_new_connection_hour, input.database_is_new_source_hour)
    input.database_suc_sql_hour >= 0.9
    input.database_outlier_max_score_summary_hour >= 0.9
    database_is_valid_admin_or_sensitive_critical(input.database_is_admin_hour, input.database_sensitive_obj_hour, input.database_sensitive_obj_day)}
else := {"rule_id": "database_suspicious_activities_high", "severity": "HIGH2"} if {
database_is_valid_connection_high(input.database_is_new_connection_hour, input.database_is_new_source_hour)
    input.database_suc_sql_hour >= 0.8
    input.database_suc_sql_hour < 0.9
    input.database_outlier_max_score_summary_hour >= 0.8
    input.database_outlier_max_score_summary_hour < 0.9
    database_is_valid_admin_or_sensitive_high(input.database_is_admin_hour, input.database_sensitive_obj_hour, input.database_sensitive_obj_day)}
# Rule ID and Severity mappings
else := {"rule_id": "database_suspicious_activities_medium", "severity": "MEDIUM2"} if {
database_is_valid_connection_medium(input.database_is_new_connection_hour, input.database_is_new_source_hour)
    input.database_suc_sql_hour >= 0.6
    input.database_suc_sql_hour < 0.8
    input.database_outlier_max_score_summary_hour >= 0.6
    input.database_outlier_max_score_summary_hour < 0.8
    database_is_valid_admin_or_sensitive_medium(input.database_is_admin_hour, input.database_sensitive_obj_hour, input.database_sensitive_obj_day)}
else := {"rule_id": "database_suspicious_activities_low", "severity": "LOW2"} if {
    database_is_valid_connection_low(input.database_is_new_connection_hour, input.database_is_new_source_hour)
    input.database_suc_sql_hour >= 0.3
    input.database_suc_sql_hour < 0.6
    input.database_outlier_max_score_summary_hour >= 0.3
    input.database_outlier_max_score_summary_hour < 0.6
    database_is_valid_admin_or_sensitive_low(input.database_is_admin_hour, input.database_sensitive_obj_hour, input.database_sensitive_obj_day)
}
# Helper rule to check for critical connection conditions
database_is_valid_connection_critical(connection_hour, source_hour) if {
    connection_hour == 1
} else if {
    source_hour == 1
}
# Helper rule to check for high connection conditions
database_is_valid_connection_high(connection_hour, source_hour) if {
    connection_hour == 1
    source_hour == 1
}
# Helper rule to check for medium connection conditions
database_is_valid_connection_medium(connection_hour, source_hour) if {
    connection_hour == 1
    source_hour == 1
}
# Helper rule to check for low connection conditions
database_is_valid_connection_low(connection_hour, source_hour) if {
    connection_hour == 1
    source_hour == 1
}
# Helper rule to check admin condition or sensitive object conditions for critical severity
database_is_valid_admin_or_sensitive_critical(admin_hour, sensitive_obj_hour, sensitive_obj_day) if {
    admin_hour == 1
} else if {
    sensitive_obj_hour >= 0.9
    sensitive_obj_day >= 0.8
}
# Helper rule to check admin condition or sensitive object conditions for high severity
database_is_valid_admin_or_sensitive_high(admin_hour, sensitive_obj_hour, sensitive_obj_day) if {
    admin_hour == 1
} else if {
    sensitive_obj_hour >= 0.8
    sensitive_obj_hour < 0.9
    sensitive_obj_day >= 0.6
    sensitive_obj_day < 0.8
}
# Helper rule to check admin condition or sensitive object conditions for medium severity
database_is_valid_admin_or_sensitive_medium(admin_hour, sensitive_obj_hour, sensitive_obj_day) if {
    admin_hour == 1
} else if {
    sensitive_obj_hour >= 0.6
    sensitive_obj_hour < 0.8
    sensitive_obj_day >= 0.3
    sensitive_obj_day < 0.6
}
# Helper rule to check admin condition or sensitive object conditions for low severity
database_is_valid_admin_or_sensitive_low(admin_hour, sensitive_obj_hour, sensitive_obj_day) if {
    admin_hour == 1
} else if {
    sensitive_obj_hour >= 0.3
    sensitive_obj_hour < 0.6
    sensitive_obj_day < 0.3
}
#3 ------------------- High intensity of Outlier and Violations --------------------------
# Rule ID and Severity mappings
severity3 = {"rule_id": "database_high_outlier_large_activities_critical", "severity": "CRITICAL3"} if {

    database_critical_condition_high_intensity

 }
else := {"rule_id": "database_high_outlier_large_activities_high", "severity": "HIGH3"} if {
        database_high_condition_high_intensity
}
# Rule ID and Severity mappings
else :=  {"rule_id": "database_high_outlier_large_activities_medium", "severity": "MEDIUM3"} if {
    database_medium_condition_high_intensity
}
else :=  {"rule_id": "database_high_outlier_large_activities_low", "severity": "LOW3"} if {
    database_low_condition_high_intensity
}
# Critical Condition: Check for the critical severity rules
database_critical_condition_high_intensity if {
    input.database_total_count_activity_hour >= 0.9
    input.database_total_count_activity_day >= 0.8
    input.database_outlier_max_score_summary_hour >= 0.9
    input.database_outlier_max_score_summary_day >= 0.8
    input.database_count_violations_hour >= 0.9
    input.database_count_violations_day >= 0.8
    database_sensitive_or_login_condition
}
# High Condition: Check for the high severity rules
database_high_condition_high_intensity if {
    input.database_total_count_activity_hour >= 0.8
    input.database_total_count_activity_hour < 0.9
    input.database_total_count_activity_day >= 0.6
    input.database_total_count_activity_day < 0.8
    input.database_outlier_max_score_summary_hour >= 0.8
    input.database_outlier_max_score_summary_hour < 0.9
    input.database_outlier_max_score_summary_day >= 0.6
    input.database_outlier_max_score_summary_day < 0.8
    input.database_count_violations_hour >= 0.8
    input.database_count_violations_hour < 0.9
    input.database_count_violations_day >= 0.6
    input.database_count_violations_day < 0.8
    database_sensitive_or_login_condition_high
}
# Medium Condition: Check for the medium severity rules
database_medium_condition_high_intensity if{
    input.database_total_count_activity_hour >= 0.6
    input.database_total_count_activity_hour < 0.8
    input.database_total_count_activity_day >= 0.3
    input.database_total_count_activity_day < 0.6
    input.database_outlier_max_score_summary_hour >= 0.6
    input.database_outlier_max_score_summary_hour < 0.8
    input.database_outlier_max_score_summary_day >= 0.3
    input.database_outlier_max_score_summary_day < 0.6
    input.database_count_violations_hour >= 0.6
    input.database_count_violations_hour < 0.8
    input.database_count_violations_day >= 0.3
    input.database_count_violations_day < 0.6
    database_medium_sensitive_or_login_condition
}
# Low Condition: Check for the low severity rules
database_low_condition_high_intensity if {
    input.database_total_count_activity_hour >= 0.3
    input.database_total_count_activity_hour < 0.6
    input.database_total_count_activity_day < 0.3
    input.database_outlier_max_score_summary_hour >= 0.3
    input.database_outlier_max_score_summary_hour < 0.6
    input.database_outlier_max_score_summary_day < 0.3
    input.database_count_violations_hour >= 0.3
    input.database_count_violations_hour < 0.6
    input.database_count_violations_day < 0.3
    database_low_sensitive_or_login_condition
}
database_sensitive_or_login_condition if {
    input.database_sensitive_obj_hour >= 0.9
    input.database_sensitive_obj_day >= 0.8
}
else if {
    input.database_login_failed_exceptions_hour >= 0.9
    input.database_login_failed_exceptions_day >= 0.8
}

database_sensitive_or_login_condition_high if {
    input.database_sensitive_obj_hour >= 0.2
    input.database_sensitive_obj_day >= 0.2
}
else if {
     input.database_login_failed_exceptions_hour >= 0.2
     input.database_login_failed_exceptions_day >= 0.2
}
database_medium_sensitive_or_login_condition if {
     input.database_sensitive_obj_hour >= 0.2
     input.database_sensitive_obj_day >= 0.2
}
else if {
    input.database_login_failed_exceptions_hour >= 0.2
    input.database_login_failed_exceptions_day >= 0.2
}
database_low_sensitive_or_login_condition if {
     input.database_sensitive_obj_hour >= 0.2
     input.database_sensitive_obj_day >= 0.2
}
else if {
    input.database_login_failed_exceptions_hour >= 0.2
    input.database_login_failed_exceptions_day >= 0.2
}
#4 ------------------- High intensity of Outlier and Violations --------------------------

severity4 := {"rule_id": "database_high_violation_large_activities_critical", "severity": "CRITICAL4"} if {
	input.database_total_count_activity_hour >= 0.9
	input.database_total_count_activity_day >= 0.8
	database_outlier_or_violation_critical
	database_key_characteristics_critical
} else := {"rule_id": "database_high_violation_large_activities_high", "severity": "HIGH4"} if {
	input.database_total_count_activity_hour >= 0.8
	input.database_total_count_activity_hour < 0.9
	input.database_total_count_activity_day >= 0.6
	input.database_total_count_activity_day < 0.8
	database_outlier_or_violation_high
	database_key_characteristics_high
} else := {"rule_id": "database_high_violation_large_activities_medium", "severity": "MEDIUM4"} if {
	input.database_total_count_activity_hour >= 0.6
	input.database_total_count_activity_hour < 0.8
	input.database_total_count_activity_day >= 0.3
	input.database_total_count_activity_day < 0.6
	database_outlier_or_violation_medium
	database_key_characteristics_medium
} else := {"rule_id": "database_high_violation_large_activities_low", "severity": "LOW4"} if {
	input.database_total_count_activity_hour >= 0.3
	input.database_total_count_activity_hour < 0.6
	input.database_total_count_activity_day < 0.3
	database_outlier_or_violation_low
	database_key_characteristics_low
}

# Helper functions for OR logic

# Mandatory Features - Critical
database_outlier_or_violation_critical if {
	input.database_outlier_max_score_summary_hour >= 0.9
	input.database_outlier_max_score_summary_day >= 0.8
}

database_outlier_or_violation_critical if {
	input.database_count_violation_hour >= 0.9
	input.database_count_violation_day >= 0.8
}

# Mandatory Features - High
database_outlier_or_violation_high if {
	input.database_outlier_max_score_summary_hour >= 0.8
	input.database_outlier_max_score_summary_hour < 0.9
	input.database_outlier_max_score_summary_day >= 0.6
	input.database_outlier_max_score_summary_day < 0.8
}

database_outlier_or_violation_high if {
	input.database_count_violation_hour >= 0.8
	input.database_count_violation_hour < 0.9
	input.database_count_violation_day >= 0.6
	input.database_count_violation_day < 0.8
}

# Mandatory Features - Medium
database_outlier_or_violation_medium if {
	input.database_outlier_max_score_summary_hour >= 0.6
	input.database_outlier_max_score_summary_hour < 0.8
	input.database_outlier_max_score_summary_day >= 0.3
	input.database_outlier_max_score_summary_day < 0.6
}

database_outlier_or_violation_medium if {
	input.database_count_violation_hour >= 0.6
	input.database_count_violation_hour < 0.8
	input.database_count_violation_day >= 0.3
	input.database_count_violation_day < 0.6
}

# Mandatory Features - Low
database_outlier_or_violation_low if {
	input.database_outlier_max_score_summary_hour >= 0.3
	input.database_outlier_max_score_summary_hour < 0.6
	input.database_outlier_max_score_summary_day < 0.3
}

database_outlier_or_violation_low if {
	input.database_count_violation_hour >= 0.3
	input.database_count_violation_hour < 0.6
	input.database_count_violation_day < 0.3
}

# Key Characteristics - Critical
database_key_characteristics_critical if {
	input.database_sensitive_obj_hour >= 0.9
	input.database_sensitive_obj_day >= 0.8
}

database_key_characteristics_critical if {
	input.database_va_critical_week >= 0.9
}

database_key_characteristics_critical if {
	input.database_login_failed_exception_hour >= 0.9
	input.database_login_failed_exception_day >= 0.8
}

# Key Characteristics - High
database_key_characteristics_high if {
	input.database_sensitive_obj_hour >= 0.2
	input.database_sensitive_obj_day >= 0.2
}

database_key_characteristics_high if {
	input.database_va_critical_week >= 0.8
	input.database_va_critical_week < 0.9
}

database_key_characteristics_high if {
	input.database_login_failed_exception_hour >= 0.2
	input.database_login.login_failed_exception_day >= 0.2
}

# Key Characteristics - Medium
database_key_characteristics_medium if {
	input.database_sensitive_obj_hour >= 0.2
	input.database_sensitive_obj_day >= 0.2
}

database_key_characteristics_medium if {
	input.database_va_critical_week >= 0.6
	input.database_va_critical_week < 0.8
}

database_key_characteristics_medium if {
	input.database_login_failed_exception_hour >= 0.2
	input.database_login_failed_exception_day >= 0.2
}

# Key Characteristics - Low
database_key_characteristics_low if {
	input.database_sensitive_obj_hour >= 0.2
	input.database_sensitive_obj_day >= 0.2
}

database_key_characteristics_low if {
	input.database_va_critical_week >= 0.3
	input.database_va_critical_week < 0.6
}

database_key_characteristics_low if {
	input.database_login_failed_exception_hour >= 0.2
	input.database_login.login_failed_exception_day >= 0.2
}


#5 ------------------- High Data Manipulation--------------------------
severity5 := {"rule_id": "database_high_data_manipulation_high", "severity": "HIGH5"} if {
    database_mandatory_features_high
    input.database_outlier_max_score_summary_hour >= 0.8
    input.database_is_admin_hour == 1
    input.database_sensitive_obj_hour >= 0.8
    input.database_sensitive_obj_day >= 0.6
} else := {"rule_id": "database_high_data_manipulation_medium", "severity": "MEDIUM5"} if {
    database_mandatory_features_medium
    input.database_outlier_max_score_summary_hour >= 0.6
    input.database_outlier_max_score_summary_hour < 0.8
    input.database_is_admin_hour == 1
    input.database_sensitive_obj_hour >= 0.6
    input.database_sensitive_obj_hour < 0.8
    input.database_sensitive_obj_day >= 0.3
    input.database_sensitive_obj_day < 0.6
    not database_mandatory_features_high
} else := {"rule_id": "database_high_data_manipulation_low", "severity": "LOW5"} if {
    database_mandatory_features_low
    input.database_outlier_max_score_summary_hour >= 0.3
    input.database_outlier_max_score_summary_hour < 0.6
    input.database_is_admin_hour == 1
    input.database_sensitive_obj_hour >= 0.3
    input.database_sensitive_obj_hour < 0.6
    input.database_sensitive_obj_day < 0.3
    not database_mandatory_features_high
    not database_mandatory_features_medium
}
# Helper functions for OR logic
# Mandatory Features - High
database_mandatory_features_high if {
    input.database_count_dml_hour >= 0.8
}
database_mandatory_features_high if {
    database_high_volume
}
# Mandatory Features - Medium
database_mandatory_features_medium if {
    input.database_count_dml_hour >= 0.6
    input.database_count_dml_hour < 0.8
}
database_mandatory_features_medium if {
    database_high_volume
}
# Mandatory Features - Low
database_mandatory_features_low if {
    input.database_count_dml_hour >= 0.3
    input.database_count_dml_hour < 0.6
}
database_mandatory_features_low if {
    database_high_volume
}
# High Volume
database_high_volume if {
    input.database_is_high_volume_delete_hour == 1
    input.database_is_high_volume_delete_day == 1
}
database_high_volume if {
    input.database_is_high_volume_dml_hour == 1
    input.database_is_high_volume_dml_day == 1
}
database_high_volume if {
    input.database_is_high_volume_alter_hour == 1
    input.database_is_high_volume_alter_day == 1
}
database_high_volume if {
    input.database_is_high_volume_drop_hour == 1
    input.database_is_high_volume_drop_day == 1
}
database_high_volume if {
    input.database_is_high_volume_schema_element_rm_hour == 1
    input.database_is_high_volume_schema_element_rm_day == 1
}
#6 ------------------- High Login Failed Exception --------------------------

severity6 = {"rule_id": "database_high_login_medium", "severity": "MEDIUM6"} if {
    database_medium_condition_high_login
}
else := {"rule_id": "database_high_login_low", "severity": "LOW6"} if {
    database_low_condition_high_login
}
# Medium Condition: Check for the medium severity rules
database_medium_condition_high_login if {
    database_connection_or_source_condition
    database_login_failed_exception_condition
    database_successful_sql_or_activity_condition
    database_admin_or_sensitive_condition
}
# Connection or Source Condition: Either a new connection or a new source is observed
database_connection_or_source_condition if {
    database_is_new_connection_condition
}
else if {
    database_is_new_source_condition
}
# Login Failed Exception Condition: Either login failed exceptions are high in the hour or the day
database_login_failed_exception_condition if {
    database_login_failed_exception_hour_condition
}
else if {
    database_login_failed_exception_day_condition
}
# Successful SQL or Activity Condition: Either successful SQL operations or high count of activities in the hour
database_successful_sql_or_activity_condition if {
    database_suc_sql_hour_condition
}
else if {
    input.database_count_activity_hour >= 0.6
}
# Admin or Sensitive Object Condition: Either admin hour or sensitive object conditions are met
database_admin_or_sensitive_condition if {
    input.database_is_admin_hour == 1
}
else if {
    input.database_sensitive_obj_hour >= 0.6
    input.database_sensitive_obj_day >= 0.3
}
database_is_new_connection_condition if {
    input.database_is_new_connection_hour == 1
}
database_is_new_source_condition if {
    input.database_is_new_source_hour == 1
}
database_login_failed_exception_hour_condition if {
    input.database_login_failed_exception_hour >= 0.6
}
database_login_failed_exception_day_condition if {
    input.database_login_failed_exception_day >= 0.3
}
database_suc_sql_hour_condition if {
    input.database_SUC_SQL_hour >= 0.6
}
database_low_condition_high_login if {
    database_low_is_new_connection_or_source_condition
    database_low_login_failed_condition
    database_low_suc_sql_or_count_activity_condition
    database_low_admin_or_sensitive_obj_condition
}
database_low_is_new_connection_or_source_condition if {
    input.database_is_new_connection_hour == 1
} else if {
    input.database_is_new_source_hour == 1
}
database_low_login_failed_condition if {
    input.database_login_failed_exception_hour >= 0.3
    input.database_login_failed_exception_hour < 0.6
} else if {
    input.database_login_failed_exception_day < 0.3
}
database_low_suc_sql_or_count_activity_condition if {
    input.database_SUC_SQL_hour >= 0.3
    input.database_SUC_SQL_hour < 0.6
} else if {
    input.database_count_activity_hour >= 0.3
    input.database_count_activity_hour < 0.6
}
database_low_admin_or_sensitive_obj_condition if {
    input.database_is_admin_hour == 1
} else if {
    input.database_sensitive_obj_hour >= 0.3
    input.database_sensitive_obj_hour < 0.6
    input.database_sensitive_obj_day < 0.3
}