package policies

import rego.v1


default severity = "NORMAL"

#3 ------------------- High intensity of Outlier and Violations --------------------------

# Set severity to CRITICAL if all critical conditions are met
severity = "High Intensity - CRITICAL" if {
    critical_condition_high_intensity
}
# Set severity to HIGH if critical conditions are not met but high conditions are
else = "High Intensity - HIGH" if {
    high_condition_high_intensity
}
# Set severity to MEDIUM if neither critical nor high conditions are met but medium conditions are
else = "High Intensity - MEDIUM" if {
    medium_condition_high_intensity
}
# Set severity to LOW if none of the above conditions are met but low conditions are
else = "High Intensity - LOW" if {
    low_condition_high_intensity
}
# Critical Condition: Check for the critical severity rules
critical_condition_high_intensity if {
    total_count_activity_condition
    outlier_max_score_condition
    count_violations_condition
    sensitive_or_va_or_login_condition
}

# High Condition: Check for the high severity rules
high_condition_high_intensity if {
    high_total_count_activity_condition
    high_outlier_max_score_condition
    high_count_violations_condition
    sensitive_or_va_or_login_condition_high
}

# Medium Condition: Check for the medium severity rules
medium_condition_high_intensity if{
    medium_total_activity_condition
    medium_outlier_max_score_condition
    medium_count_violations_condition
    medium_sensitive_or_va_or_login_condition
}
# Low Condition: Check for the low severity rules
low_condition_high_intensity if {
    low_total_count_activity_condition
    low_outlier_max_score_condition
    low_count_violations_condition
    low_sensitive_or_va_or_login_condition
}

# --- Critical Helper Rules ---

# Check total count activity for both hour and day
total_count_activity_condition if {
    total_count_activity_hour_condition
    total_count_activity_day_condition
}

total_count_activity_hour_condition if {
    input.total_count_activity_hour >= 0.9
}

total_count_activity_day_condition if {
    input.total_count_activity_day >= 0.8
}

# Check outlier max score for both hour and day
outlier_max_score_condition if {
    outlier_max_score_summary_hour_condition
    outlier_max_score_summary_day_condition
}

outlier_max_score_summary_hour_condition if {
    input.outlier_max_score_summary_hour >= 0.9
}

outlier_max_score_summary_day_condition if {
    input.outlier_max_score_summary_day >= 0.8
}

# Check count violations for both hour and day
count_violations_condition if {
    count_violations_hour_condition
    count_violations_day_condition
}

count_violations_hour_condition if {
    input.count_violations_hour >= 0.9
}

count_violations_day_condition if {
    input.count_violations_day >= 0.8
}

sensitive_or_va_or_login_condition if {
    sensitive_obj_condition
}

else if {
    va_critical_week_condition
}

else if {
    login_failed_exceptions_condition
}

# Check sensitive_obj for both hour and day
sensitive_obj_condition if {
    sensitive_obj_hour_condition
    sensitive_obj_day_condition
}

sensitive_obj_hour_condition if {
    input.sensitive_obj_hour >= 0.9
}

sensitive_obj_day_condition if {
    input.sensitive_obj_day >= 0.8
}

# Check va_critical_week
va_critical_week_condition if {
    input.va_critical_week >= 0.9
}

# Check login_failed_exceptions for both hour and day
login_failed_exceptions_condition if {
    login_failed_exceptions_hour_condition
    login_failed_exceptions_day_condition
}

login_failed_exceptions_hour_condition if {
    input.login_failed_exceptions_hour >= 0.9
}

login_failed_exceptions_day_condition if {
    input.login_failed_exceptions_day >= 0.8
}
# High Helper Rules 
high_total_count_activity_condition if {
    input.total_count_activity_hour >= 0.8
    input.total_count_activity_hour < 0.9
    input.total_count_activity_day >= 0.6
    input.total_count_activity_day < 0.8
}

high_outlier_max_score_condition if {
    input.outlier_max_score_summary_hour >= 0.8
    input.outlier_max_score_summary_hour < 0.9
    input.outlier_max_score_summary_day >= 0.6
    input.outlier_max_score_summary_day < 0.8
}

high_count_violations_condition if {
    input.count_violations_hour >= 0.8
    input.count_violations_hour < 0.9
    input.count_violations_day >= 0.6
    input.count_violations_day < 0.8
}
# High: Apply if-else style for sensitive, va_critical_week, or login failed exceptions
sensitive_or_va_or_login_condition_high if {
    sensitive_obj_high_condition
}

else if {
    va_critical_week_high_condition
}

else if {
    login_failed_exceptions_high_condition
}

sensitive_obj_high_condition if {
    input.sensitive_obj_hour >= 0.2
    input.sensitive_obj_day >= 0.2
}

va_critical_week_high_condition if {
    input.va_critical_week >= 0.8
    input.va_critical_week < 0.9
}

login_failed_exceptions_high_condition if {
    input.login_failed_exceptions_hour >= 0.2
    input.login_failed_exceptions_day >= 0.2
}

# Medium Helper Rules 

# Medium total activity condition
medium_total_activity_condition if{
    input.total_count_activity_hour >= 0.6
    input.total_count_activity_hour < 0.8
    input.total_count_activity_day >= 0.3
    input.total_count_activity_day < 0.6
}

# Medium outlier score condition
medium_outlier_max_score_condition if{
    input.outlier_max_score_summary_hour >= 0.6
    input.outlier_max_score_summary_hour < 0.8
    input.outlier_max_score_summary_day >= 0.3
    input.outlier_max_score_summary_day < 0.6
}

# Medium count violations condition
medium_count_violations_condition if{
    input.count_violations_hour >= 0.6
    input.count_violations_hour < 0.8
    input.count_violations_day >= 0.3
    input.count_violations_day < 0.6
}

# Medium sensitive object, VA critical week, or login failed exceptions condition
medium_sensitive_or_va_or_login_condition if {
    medium_sensitive_obj_condition
}

else if {
    medium_va_critical_week_condition
}

else if {
    medium_login_failed_exceptions_condition
}

# Medium sensitive object condition
medium_sensitive_obj_condition if{
    input.sensitive_obj_hour >= 0.2
    input.sensitive_obj_day >= 0.2
}

# Medium VA critical week condition
medium_va_critical_week_condition if{
    input.va_critical_week >= 0.6
    input.va_critical_week < 0.8
}

# Medium login failed exceptions condition
medium_login_failed_exceptions_condition if{
    input.login_failed_exceptions_hour >= 0.2
    input.login_failed_exceptions_day >= 0.2
}

# Low Helper Rules
low_total_count_activity_condition if {
    input.total_count_activity_hour >= 0.3
    input.total_count_activity_hour < 0.6
    input.total_count_activity_day < 0.3
}

low_outlier_max_score_condition if {
    input.outlier_max_score_summary_hour >= 0.3
    input.outlier_max_score_summary_hour < 0.6
    input.outlier_max_score_summary_day < 0.3
}

low_count_violations_condition if {
    input.count_violations_hour >= 0.3
    input.count_violations_hour < 0.6
    input.count_violations_day < 0.3
}

low_sensitive_or_va_or_login_condition if {
    low_sensitive_condition
}
else if {
    low_va_critical_week_condition
}
else if {
    low_login_failed_exceptions_condition
}

low_sensitive_condition if {
    input.sensitive_obj_hour >= 0.2
    input.sensitive_obj_day >= 0.2
}

low_va_critical_week_condition if {
    input.va_critical_week >= 0.3
    input.va_critical_week < 0.6
}

low_login_failed_exceptions_condition if {
    input.login_failed_exceptions_hour >= 0.2
    input.login_failed_exceptions_day >= 0.2
}
