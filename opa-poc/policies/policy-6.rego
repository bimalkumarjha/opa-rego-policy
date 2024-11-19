package policies

import rego.v1

#6 ------------------- High Login Failed Exception --------------------------
# Define a rule that returns both the rule ID and severity
default severity = ""

# Rule ID and Severity mappings
severity = {"rule_id": "db_user_high_login_medium", "severity": "MEDIUM"} if {
    medium_condition_high_login
}

severity = {"rule_id": "db_user_high_login_low", "severity": "LOW"} if {
    low_condition_high_login
}
# Medium Condition: Check for the medium severity rules
medium_condition_high_login if {
    connection_or_source_condition
    login_failed_exception_condition
    successful_sql_or_activity_condition
    admin_or_sensitive_condition
}

# Connection or Source Condition: Either a new connection or a new source is observed
connection_or_source_condition if {
    is_new_connection_condition
}
else if {
    is_new_source_condition
}
# Login Failed Exception Condition: Either login failed exceptions are high in the hour or the day
login_failed_exception_condition if {
    login_failed_exception_hour_condition
}
else if {
    login_failed_exception_day_condition
}

# Successful SQL or Activity Condition: Either successful SQL operations or high count of activities in the hour
successful_sql_or_activity_condition if {
    suc_sql_hour_condition
}
else if {
    input.count_activity_hour >= 0.6

}

# Admin or Sensitive Object Condition: Either admin hour or sensitive object conditions are met
admin_or_sensitive_condition if {
    input.is_admin_hour == 1
}
else if {
    input.sensitive_obj_hour >= 0.6
    input.sensitive_obj_day >= 0.3
}

is_new_connection_condition if {
    input.is_new_connection_hour == 1
}

is_new_source_condition if {
    input.is_new_source_hour == 1
}

login_failed_exception_hour_condition if {
    input.login_failed_exception_hour >= 0.6
}

login_failed_exception_day_condition if {
    input.login_failed_exception_day >= 0.3
}

suc_sql_hour_condition if {
    input.SUC_SQL_hour >= 0.6
}

low_condition_high_login if {
    low_is_new_connection_or_source_condition
    low_login_failed_condition
    low_suc_sql_or_count_activity_condition
    low_admin_or_sensitive_obj_condition
}

low_is_new_connection_or_source_condition if {
    input.is_new_connection_hour == 1
} else if {
    input.is_new_source_hour == 1
}

low_login_failed_condition if {
    input.login_failed_exception_hour >= 0.3
    input.login_failed_exception_hour < 0.6
} else if {
    input.login_failed_exception_day < 0.3
}

low_suc_sql_or_count_activity_condition if {
    input.SUC_SQL_hour >= 0.3
    input.SUC_SQL_hour < 0.6
} else if {
    input.count_activity_hour >= 0.3
    input.count_activity_hour < 0.6
}

low_admin_or_sensitive_obj_condition if {
    input.is_admin_hour == 1
} else if {
    input.sensitive_obj_hour >= 0.3
    input.sensitive_obj_hour < 0.6
    input.sensitive_obj_day < 0.3
}




