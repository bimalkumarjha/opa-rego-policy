package policies.dbuser

import rego.v1

#1 ------------------- Excessive Data Activities Performed by the Privileged user --------------------------
# Rule ID and Severity mappings
severity = {"rule_id": "dbuser_excessive_data_activities_critical", "severity": "CRITICAL"} if {
    dbuser_critical_condition
}
else := {"rule_id": "dbuser_excessive_data_activities_high", "severity": "HIGH"} if {
    dbuser_high_condition
}
# Rule ID and Severity mappings
else :=  {"rule_id": "dbuser_excessive_data_activities_medium", "severity": "MEDIUM"} if {
    dbuser_medium_condition
}
else :=  {"rule_id": "dbuser_excessive_data_activities_low", "severity": "LOW"} if {
    dbuser_low_condition
}
# Critical Condition: Check for the critical severity rules
dbuser_critical_condition if {
    input.dbuser_is_high_volume_select_hour == 1
    input.dbuser_is_high_volume_select_day == 1
    input.dbuser_outlier_max_score_summary_hour >= 0.9
    input.dbuser_is_admin_hour == 1
    input.dbuser_sensitive_obj_hour >= 0.9
    input.dbuser_sensitive_obj_day >= 0.8
}
# High Condition: Check for the high severity rules
dbuser_high_condition if{
    input.dbuser_is_high_volume_select_hour == 1
    input.dbuser_is_high_volume_select_day == 1
    input.dbuser_outlier_max_score_summary_hour >= 0.8
    input.dbuser_outlier_max_score_summary_hour < 0.9
    input.dbuser_is_admin_hour == 1
    input.dbuser_sensitive_obj_hour >= 0.8
    input.dbuser_sensitive_obj_hour < 0.9
    input.dbuser_sensitive_obj_day >= 0.6
    input.dbuser_sensitive_obj_day < 0.8
}
# Medium Condition: Check for the medium severity rules
dbuser_medium_condition if{
    dbuser_medium_high_volume_select_condition_or_outlier
    dbuser_medium_admin_hour_condition
    dbuser_medium_sensitive_obj_hour_condition
    dbuser_medium_sensitive_obj_day_condition
}
# Low Condition: Check for the low severity rules
dbuser_low_condition if {
    dbuser_low_high_volume_select_condition_or_outlier
    input.dbuser_is_admin_hour == 1
    input.dbuser_sensitive_obj_hour >= 0.3
    input.dbuser_sensitive_obj_hour < 0.6   
    input.dbuser_sensitive_obj_day < 0.3
}
#  Medium Helper Rules 
# This condition allows for either high volume select OR outlier condition to pass for medium severity.
dbuser_medium_high_volume_select_condition_or_outlier if{
    dbuser_some_condition_is_true
}
dbuser_some_condition_is_true if{
    dbuser_is_high_volume_select_for_medium
}
dbuser_some_condition_is_true if{
    dbuser_is_outlier_max_score_for_medium
}
dbuser_is_high_volume_select_for_medium if{
    input.dbuser_is_high_volume_select_hour == 1
    input.dbuser_is_high_volume_select_day == 1
}
dbuser_is_outlier_max_score_for_medium if{
    input.dbuser_outlier_max_score_summary_hour >= 0.6
    input.dbuser_outlier_max_score_summary_hour < 0.8
}
dbuser_medium_admin_hour_condition if{
    input.dbuser_is_admin_hour == 1
}
dbuser_medium_sensitive_obj_hour_condition if{
    input.dbuser_sensitive_obj_hour >= 0.6
    input.dbuser_sensitive_obj_hour < 0.8
}
dbuser_medium_sensitive_obj_day_condition if{
    input.dbuser_sensitive_obj_day >= 0.3
    input.dbuser_sensitive_obj_day < 0.6
}
#  Low Helper Rules 
dbuser_low_high_volume_select_condition_or_outlier if {
    dbuser_some_low_condition_is_true
}
dbuser_some_low_condition_is_true if {
    input.dbuser_is_high_volume_select_hour == 1
    input.dbuser_is_high_volume_select_day == 1
}
dbuser_some_low_condition_is_true if {
     input.dbuser_outlier_max_score_summary_hour >= 0.3
     input.dbuser_outlier_max_score_summary_hour < 0.6
}
#2 ------------------- Suspicious activities Performed on Sensitive Data --------------------------
# Rule ID and Severity mappings
severity = {"rule_id": "dbuser_suspicious_activities_critical", "severity": "CRITICAL"} if {
 dbuser_is_valid_connection_critical(input.dbuser_is_new_connection_hour, input.dbuser_is_new_source_hour)
    input.dbuser_suc_sql_hour >= 0.9
    input.dbuser_outlier_max_score_summary_hour >= 0.9
    dbuser_is_valid_admin_or_sensitive_critical(input.dbuser_is_admin_hour, input.dbuser_sensitive_obj_hour, input.dbuser_sensitive_obj_day)}
else := {"rule_id": "dbuser_suspicious_activities_high", "severity": "HIGH"} if {
dbuser_is_valid_connection_high(input.dbuser_is_new_connection_hour, input.dbuser_is_new_source_hour)
    input.dbuser_suc_sql_hour >= 0.8
    input.dbuser_suc_sql_hour < 0.9
    input.dbuser_outlier_max_score_summary_hour >= 0.8
    input.dbuser_outlier_max_score_summary_hour < 0.9
    dbuser_is_valid_admin_or_sensitive_high(input.dbuser_is_admin_hour, input.dbuser_sensitive_obj_hour, input.dbuser_sensitive_obj_day)}
# Rule ID and Severity mappings
else := {"rule_id": "dbuser_suspicious_activities_medium", "severity": "MEDIUM"} if {
dbuser_is_valid_connection_medium(input.dbuser_is_new_connection_hour, input.dbuser_is_new_source_hour)
    input.dbuser_suc_sql_hour >= 0.6
    input.dbuser_suc_sql_hour < 0.8
    input.dbuser_outlier_max_score_summary_hour >= 0.6
    input.dbuser_outlier_max_score_summary_hour < 0.8
    dbuser_is_valid_admin_or_sensitive_medium(input.dbuser_is_admin_hour, input.dbuser_sensitive_obj_hour, input.dbuser_sensitive_obj_day)}
else := {"rule_id": "dbuser_suspicious_activities_low", "severity": "LOW"} if {
    dbuser_is_valid_connection_low(input.dbuser_is_new_connection_hour, input.dbuser_is_new_source_hour)
    input.dbuser_suc_sql_hour >= 0.3
    input.dbuser_suc_sql_hour < 0.6
    input.dbuser_outlier_max_score_summary_hour >= 0.3
    input.dbuser_outlier_max_score_summary_hour < 0.6
    dbuser_is_valid_admin_or_sensitive_low(input.dbuser_is_admin_hour, input.dbuser_sensitive_obj_hour, input.dbuser_sensitive_obj_day)
}
# Helper rule to check for critical connection conditions
dbuser_is_valid_connection_critical(connection_hour, source_hour) if {
    connection_hour == 1
} else if {
    source_hour == 1
}
# Helper rule to check for high connection conditions
dbuser_is_valid_connection_high(connection_hour, source_hour) if {
    connection_hour == 1
    source_hour == 1
}
# Helper rule to check for medium connection conditions
dbuser_is_valid_connection_medium(connection_hour, source_hour) if {
    connection_hour == 1
    source_hour == 1
}
# Helper rule to check for low connection conditions
dbuser_is_valid_connection_low(connection_hour, source_hour) if {
    connection_hour == 1
    source_hour == 1
}
# Helper rule to check admin condition or sensitive object conditions for critical severity
dbuser_is_valid_admin_or_sensitive_critical(admin_hour, sensitive_obj_hour, sensitive_obj_day) if {
    admin_hour == 1
} else if {
    sensitive_obj_hour >= 0.9
    sensitive_obj_day >= 0.8
}
# Helper rule to check admin condition or sensitive object conditions for high severity
dbuser_is_valid_admin_or_sensitive_high(admin_hour, sensitive_obj_hour, sensitive_obj_day) if {
    admin_hour == 1
} else if {
    sensitive_obj_hour >= 0.8
    sensitive_obj_hour < 0.9
    sensitive_obj_day >= 0.6
    sensitive_obj_day < 0.8
}
# Helper rule to check admin condition or sensitive object conditions for medium severity
dbuser_is_valid_admin_or_sensitive_medium(admin_hour, sensitive_obj_hour, sensitive_obj_day) if {
    admin_hour == 1
} else if {
    sensitive_obj_hour >= 0.6
    sensitive_obj_hour < 0.8
    sensitive_obj_day >= 0.3
    sensitive_obj_day < 0.6
}
# Helper rule to check admin condition or sensitive object conditions for low severity
dbuser_is_valid_admin_or_sensitive_low(admin_hour, sensitive_obj_hour, sensitive_obj_day) if {
    admin_hour == 1
} else if {
    sensitive_obj_hour >= 0.3
    sensitive_obj_hour < 0.6
    sensitive_obj_day < 0.3
}
#3 ------------------- High intensity of Outlier and Violations --------------------------
# Rule ID and Severity mappings
severity = {"rule_id": "dbuser_high_outlier_large_activities_critical", "severity": "CRITICAL"} if {
 
    dbuser_critical_condition_high_intensity

 }
else := {"rule_id": "dbuser_high_outlier_large_activities_high", "severity": "HIGH"} if {
        dbuser_high_condition_high_intensity
}
# Rule ID and Severity mappings
else :=  {"rule_id": "dbuser_high_outlier_large_activities_medium", "severity": "MEDIUM"} if {
    dbuser_medium_condition_high_intensity
}
else :=  {"rule_id": "dbuser_high_outlier_large_activities_low", "severity": "LOW"} if {
    dbuser_low_condition_high_intensity
}
# Critical Condition: Check for the critical severity rules
dbuser_critical_condition_high_intensity if {
    input.dbuser_total_count_activity_hour >= 0.9
    input.dbuser_total_count_activity_day >= 0.8
    input.dbuser_outlier_max_score_summary_hour >= 0.9
    input.dbuser_outlier_max_score_summary_day >= 0.8
    input.dbuser_count_violations_hour >= 0.9
    input.dbuser_count_violations_day >= 0.8  
    dbuser_sensitive_or_login_condition
}
# High Condition: Check for the high severity rules
dbuser_high_condition_high_intensity if {
    input.dbuser_total_count_activity_hour >= 0.8
    input.dbuser_total_count_activity_hour < 0.9
    input.dbuser_total_count_activity_day >= 0.6
    input.dbuser_total_count_activity_day < 0.8
    input.dbuser_outlier_max_score_summary_hour >= 0.8
    input.dbuser_outlier_max_score_summary_hour < 0.9
    input.dbuser_outlier_max_score_summary_day >= 0.6
    input.dbuser_outlier_max_score_summary_day < 0.8
    input.dbuser_count_violations_hour >= 0.8
    input.dbuser_count_violations_hour < 0.9
    input.dbuser_count_violations_day >= 0.6
    input.dbuser_count_violations_day < 0.8
    dbuser_sensitive_or_login_condition_high
}
# Medium Condition: Check for the medium severity rules
dbuser_medium_condition_high_intensity if{
    input.dbuser_total_count_activity_hour >= 0.6
    input.dbuser_total_count_activity_hour < 0.8
    input.dbuser_total_count_activity_day >= 0.3
    input.dbuser_total_count_activity_day < 0.6
    input.dbuser_outlier_max_score_summary_hour >= 0.6
    input.dbuser_outlier_max_score_summary_hour < 0.8
    input.dbuser_outlier_max_score_summary_day >= 0.3
    input.dbuser_outlier_max_score_summary_day < 0.6
    input.dbuser_count_violations_hour >= 0.6
    input.dbuser_count_violations_hour < 0.8
    input.dbuser_count_violations_day >= 0.3
    input.dbuser_count_violations_day < 0.6
    dbuser_medium_sensitive_or_login_condition
}
# Low Condition: Check for the low severity rules
dbuser_low_condition_high_intensity if {
    input.dbuser_total_count_activity_hour >= 0.3
    input.dbuser_total_count_activity_hour < 0.6
    input.dbuser_total_count_activity_day < 0.3
    input.dbuser_outlier_max_score_summary_hour >= 0.3
    input.dbuser_outlier_max_score_summary_hour < 0.6
    input.dbuser_outlier_max_score_summary_day < 0.3
    input.dbuser_count_violations_hour >= 0.3
    input.dbuser_count_violations_hour < 0.6
    input.dbuser_count_violations_day < 0.3
    dbuser_low_sensitive_or_login_condition
}
dbuser_sensitive_or_login_condition if {
    input.dbuser_sensitive_obj_hour >= 0.9
    input.dbuser_sensitive_obj_day >= 0.8
}
else if {
    input.dbuser_login_failed_exceptions_hour >= 0.9
    input.dbuser_login_failed_exceptions_day >= 0.8
}

dbuser_sensitive_or_login_condition_high if {
    input.dbuser_sensitive_obj_hour >= 0.2
    input.dbuser_sensitive_obj_day >= 0.2
}
else if {
     input.dbuser_login_failed_exceptions_hour >= 0.2
     input.dbuser_login_failed_exceptions_day >= 0.2
}
dbuser_medium_sensitive_or_login_condition if {
     input.dbuser_sensitive_obj_hour >= 0.2
     input.dbuser_sensitive_obj_day >= 0.2
}
else if {
    input.dbuser_login_failed_exceptions_hour >= 0.2
    input.dbuser_login_failed_exceptions_day >= 0.2
}
dbuser_low_sensitive_or_login_condition if {
     input.dbuser_sensitive_obj_hour >= 0.2
     input.dbuser_sensitive_obj_day >= 0.2
}
else if {
    input.dbuser_login_failed_exceptions_hour >= 0.2
    input.dbuser_login_failed_exceptions_day >= 0.2
}
#4 ------------------- High intensity of Outlier and Violations --------------------------

severityrule4 := {"rule_id": "dbuser_high_violation_large_activities_critical", "severity": "CRITICAL"} if {
	input.dbuser_total_count_activity_hour >= 0.9
	input.dbuser_total_count_activity_day >= 0.8
	dbuser_outlier_or_violation_critical
	dbuser_key_characteristics_critical
} else := {"rule_id": "dbuser_high_violation_large_activities_high", "severity": "HIGH"} if {
	input.dbuser_total_count_activity_hour >= 0.8
	input.dbuser_total_count_activity_hour < 0.9
	input.dbuser_total_count_activity_day >= 0.6
	input.dbuser_total_count_activity_day < 0.8
	dbuser_outlier_or_violation_high
	dbuser_key_characteristics_high
} else := {"rule_id": "dbuser_high_violation_large_activities_medium", "severity": "MEDIUM"} if {
	input.dbuser_total_count_activity_hour >= 0.6
	input.dbuser_total_count_activity_hour < 0.8
	input.dbuser_total_count_activity_day >= 0.3
	input.dbuser_total_count_activity_day < 0.6
	dbuser_outlier_or_violation_medium
	dbuser_key_characteristics_medium
} else := {"rule_id": "dbuser_high_violation_large_activities_low", "severity": "LOW"} if {
	input.dbuser_total_count_activity_hour >= 0.3
	input.dbuser_total_count_activity_hour < 0.6
	input.dbuser_total_count_activity_day < 0.3
	dbuser_outlier_or_violation_low
	dbuser_key_characteristics_low
}

# Helper functions for OR logic

# Mandatory Features - Critical
dbuser_outlier_or_violation_critical if {
	input.dbuser_outlier_max_score_summary_hour >= 0.9
	input.dbuser_outlier_max_score_summary_day >= 0.8
}

dbuser_outlier_or_violation_critical if {
	input.dbuser_count_violation_hour >= 0.9
	input.dbuser_count_violation_day >= 0.8
}

# Mandatory Features - High
dbuser_outlier_or_violation_high if {
	input.dbuser_outlier_max_score_summary_hour >= 0.8
	input.dbuser_outlier_max_score_summary_hour < 0.9
	input.dbuser_outlier_max_score_summary_day >= 0.6
	input.dbuser_outlier_max_score_summary_day < 0.8
}

dbuser_outlier_or_violation_high if {
	input.dbuser_count_violation_hour >= 0.8
	input.dbuser_count_violation_hour < 0.9
	input.dbuser_count_violation_day >= 0.6
	input.dbuser_count_violation_day < 0.8
}

# Mandatory Features - Medium
dbuser_outlier_or_violation_medium if {
	input.dbuser_outlier_max_score_summary_hour >= 0.6
	input.dbuser_outlier_max_score_summary_hour < 0.8
	input.dbuser_outlier_max_score_summary_day >= 0.3
	input.dbuser_outlier_max_score_summary_day < 0.6
}

dbuser_outlier_or_violation_medium if {
	input.dbuser_count_violation_hour >= 0.6
	input.dbuser_count_violation_hour < 0.8
	input.dbuser_count_violation_day >= 0.3
	input.dbuser_count_violation_day < 0.6
}

# Mandatory Features - Low
dbuser_outlier_or_violation_low if {
	input.dbuser_outlier_max_score_summary_hour >= 0.3
	input.dbuser_outlier_max_score_summary_hour < 0.6
	input.dbuser_outlier_max_score_summary_day < 0.3
}

dbuser_outlier_or_violation_low if {
	input.dbuser_count_violation_hour >= 0.3
	input.dbuser_count_violation_hour < 0.6
	input.dbuser_count_violation_day < 0.3
}

# Key Characteristics - Critical
dbuser_key_characteristics_critical if {
	input.dbuser_sensitive_obj_hour >= 0.9
	input.dbuser_sensitive_obj_day >= 0.8
}

dbuser_key_characteristics_critical if {
	input.dbuser_va_critical_week >= 0.9
}

dbuser_key_characteristics_critical if {
	input.dbuser_login_failed_exception_hour >= 0.9
	input.dbuser_login_failed_exception_day >= 0.8
}

# Key Characteristics - High
dbuser_key_characteristics_high if {
	input.dbuser_sensitive_obj_hour >= 0.2
	input.dbuser_sensitive_obj_day >= 0.2
}

dbuser_key_characteristics_high if {
	input.dbuser_va_critical_week >= 0.8
	input.dbuser_va_critical_week < 0.9
}

dbuser_key_characteristics_high if {
	input.dbuser_login_failed_exception_hour >= 0.2
	input.dbuser_login.login_failed_exception_day >= 0.2
}

# Key Characteristics - Medium
dbuser_key_characteristics_medium if {
	input.dbuser_sensitive_obj_hour >= 0.2
	input.dbuser_sensitive_obj_day >= 0.2
}

dbuser_key_characteristics_medium if {
	input.dbuser_va_critical_week >= 0.6
	input.dbuser_va_critical_week < 0.8
}

dbuser_key_characteristics_medium if {
	input.dbuser_login_failed_exception_hour >= 0.2
	input.dbuser_login_failed_exception_day >= 0.2
}

# Key Characteristics - Low
dbuser_key_characteristics_low if {
	input.dbuser_sensitive_obj_hour >= 0.2
	input.dbuser_sensitive_obj_day >= 0.2
}

dbuser_key_characteristics_low if {
	input.dbuser_va_critical_week >= 0.3
	input.dbuser_va_critical_week < 0.6
}

dbuser_key_characteristics_low if {
	input.dbuser_login_failed_exception_hour >= 0.2
	input.dbuser_login.login_failed_exception_day >= 0.2
}


#5 ------------------- High Data Manipulation--------------------------
severity := "High Data Manipulation - HIGH" if {
    dbuser_mandatory_features_high
    input.dbuser_outlier_max_score_summary_hour >= 0.8
    input.dbuser_is_admin_hour == 1
    input.dbuser_sensitive_obj_hour >= 0.8
    input.dbuser_sensitive_obj_day >= 0.6
} else := "High Data Manipulation - MEDIUM" if {
    dbuser_mandatory_features_medium
    input.dbuser_outlier_max_score_summary_hour >= 0.6
    input.dbuser_outlier_max_score_summary_hour < 0.8
    input.dbuser_is_admin_hour == 1
    input.dbuser_sensitive_obj_hour >= 0.6
    input.dbuser_sensitive_obj_hour < 0.8
    input.dbuser_sensitive_obj_day >= 0.3
    input.dbuser_sensitive_obj_day < 0.6
    not dbuser_mandatory_features_high
} else := "High Data Manipulation - LOW" if {
    dbuser_mandatory_features_low
    input.dbuser_outlier_max_score_summary_hour >= 0.3
    input.dbuser_outlier_max_score_summary_hour < 0.6
    input.dbuser_is_admin_hour == 1
    input.dbuser_sensitive_obj_hour >= 0.3
    input.dbuser_sensitive_obj_hour < 0.6
    input.dbuser_sensitive_obj_day < 0.3
    not dbuser_mandatory_features_high
    not dbuser_mandatory_features_medium
}
# Helper functions for OR logic
# Mandatory Features - High
dbuser_mandatory_features_high if {
    input.dbuser_count_dml_hour >= 0.8
}
dbuser_mandatory_features_high if {
    dbuser_high_volume
}
# Mandatory Features - Medium
dbuser_mandatory_features_medium if {
    input.dbuser_count_dml_hour >= 0.6
    input.dbuser_count_dml_hour < 0.8
}
dbuser_mandatory_features_medium if {
    dbuser_high_volume
}
# Mandatory Features - Low
dbuser_mandatory_features_low if {
    input.dbuser_count_dml_hour >= 0.3
    input.dbuser_count_dml_hour < 0.6
}
dbuser_mandatory_features_low if {
    dbuser_high_volume
}
# High Volume
dbuser_high_volume if {
    input.dbuser_is_high_volume_delete_hour == 1
    input.dbuser_is_high_volume_delete_day == 1
}
dbuser_high_volume if {
    input.dbuser_is_high_volume_dml_hour == 1
    input.dbuser_is_high_volume_dml_day == 1
}
dbuser_high_volume if {
    input.dbuser_is_high_volume_alter_hour == 1
    input.dbuser_is_high_volume_alter_day == 1
}
dbuser_high_volume if {
    input.dbuser_is_high_volume_drop_hour == 1
    input.dbuser_is_high_volume_drop_day == 1
}
dbuser_high_volume if {
    input.dbuser_is_high_volume_schema_element_rm_hour == 1
    input.dbuser_is_high_volume_schema_element_rm_day == 1
}
#6 ------------------- High Login Failed Exception --------------------------

severity = {"rule_id": "dbuser_high_login_medium", "severity": "MEDIUM"} if {
    dbuser_medium_condition_high_login
}
else := {"rule_id": "dbuser_high_login_low", "severity": "LOW"} if {
    dbuser_low_condition_high_login
}
# Medium Condition: Check for the medium severity rules
dbuser_medium_condition_high_login if {
    dbuser_connection_or_source_condition
    dbuser_login_failed_exception_condition
    dbuser_successful_sql_or_activity_condition
    dbuser_admin_or_sensitive_condition
}
# Connection or Source Condition: Either a new connection or a new source is observed
dbuser_connection_or_source_condition if {
    dbuser_is_new_connection_condition
}
else if {
    dbuser_is_new_source_condition
}
# Login Failed Exception Condition: Either login failed exceptions are high in the hour or the day
dbuser_login_failed_exception_condition if {
    dbuser_login_failed_exception_hour_condition
}
else if {
    dbuser_login_failed_exception_day_condition
}
# Successful SQL or Activity Condition: Either successful SQL operations or high count of activities in the hour
dbuser_successful_sql_or_activity_condition if {
    dbuser_suc_sql_hour_condition
}
else if {
    input.dbuser_count_activity_hour >= 0.6
}
# Admin or Sensitive Object Condition: Either admin hour or sensitive object conditions are met
dbuser_admin_or_sensitive_condition if {
    input.dbuser_is_admin_hour == 1
}
else if {
    input.dbuser_sensitive_obj_hour >= 0.6
    input.dbuser_sensitive_obj_day >= 0.3
}
dbuser_is_new_connection_condition if {
    input.dbuser_is_new_connection_hour == 1
}
dbuser_is_new_source_condition if {
    input.dbuser_is_new_source_hour == 1
}
dbuser_login_failed_exception_hour_condition if {
    input.dbuser_login_failed_exception_hour >= 0.6
}
dbuser_login_failed_exception_day_condition if {
    input.dbuser_login_failed_exception_day >= 0.3
}
dbuser_suc_sql_hour_condition if {
    input.dbuser_SUC_SQL_hour >= 0.6
}
dbuser_low_condition_high_login if {
    dbuser_low_is_new_connection_or_source_condition
    dbuser_low_login_failed_condition
    dbuser_low_suc_sql_or_count_activity_condition
    dbuser_low_admin_or_sensitive_obj_condition
}
dbuser_low_is_new_connection_or_source_condition if {
    input.dbuser_is_new_connection_hour == 1
} else if {
    input.dbuser_is_new_source_hour == 1
}
dbuser_low_login_failed_condition if {
    input.dbuser_login_failed_exception_hour >= 0.3
    input.dbuser_login_failed_exception_hour < 0.6
} else if {
    input.dbuser_login_failed_exception_day < 0.3
}
dbuser_low_suc_sql_or_count_activity_condition if {
    input.dbuser_SUC_SQL_hour >= 0.3
    input.dbuser_SUC_SQL_hour < 0.6
} else if {
    input.dbuser_count_activity_hour >= 0.3
    input.dbuser_count_activity_hour < 0.6
}
dbuser_low_admin_or_sensitive_obj_condition if {
    input.dbuser_is_admin_hour == 1
} else if {
    input.dbuser_sensitive_obj_hour >= 0.3
    input.dbuser_sensitive_obj_hour < 0.6
    input.dbuser_sensitive_obj_day < 0.3
}
