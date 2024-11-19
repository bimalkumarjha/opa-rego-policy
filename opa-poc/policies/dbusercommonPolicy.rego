package policies.dbuser

import future.keywords.if
import future.keywords.in


# Main rule that returns severity with rule_id
excessive_data_act := [{"severity": reason["severity"], "rule_id": reason["rule_id"]}] {
    mand_sev = mandatory_feature()
    key_sev = key_char()
    reason = get_severity(mand_sev, key_sev)
}

# Returns severity and rule_id based on mandatory and key characteristics
get_severity(mand_sev, key_sev) := {"severity": message, "rule_id": rule_id} if {
    mand_sev == key_sev
    message = mand_sev
    rule_id = rule_id_for_severity(mand_sev)
} else := {"severity": message, "rule_id": rule_id} if {
    mand_sev = "any"
    key_sev != "unknown"
    message = key_sev
    rule_id = rule_id_for_severity(key_sev)
}else := {"severity": message, "rule_id": rule_id} if{
	message=""
    rule_id=""
}

# Define the function to get rule_id based on severity
rule_id_for_severity(severity) = rule_id {
    rule_id := sprintf("dbuser_excessive_data_activities_%s", [severity])
}

# Functions for mandatory feature and key characteristics
mandatory_feature() = message {
    out_message = scoring(input.dbuser_outlier_max_score_summary_hour, 0.9, 0.8, 0.6, 0.3)
    message = mand_feat(out_message)
}

key_char() = message {
    obj_hour = scoring(input.dbuser_sensitive_obj_hour, 0.9, 0.8, 0.6, 0.3)
    obj_day = scoring(input.dbuser_sensitive_obj_day, 0.8, 0.6, 0.3, null)
    message = key_ch(obj_hour, obj_day)
}

# Mandatory feature logic
mand_feat(outlier_sev) := message if {
    outlier_sev != "unknown"
    is_high_volume_hour(input.dbuser_is_high_volume_select_hour, input.dbuser_is_high_volume_select_day)
    message = "any"
} else := message if {
	outlier_sev!= "unknown"
    message = outlier_sev
} else := message if {
    outlier_sev != "critical"
    outlier_sev != "high"
    is_high_volume_hour(input.dbuser_is_high_volume_select_hour, input.dbuser_is_high_volume_select_day)
    message = "medium"
}

# Key characteristic logic
key_ch(obj_hour_sev, obj_day_sev) := message if {
    obj_hour_sev == obj_day_sev
    input.dbuser_is_admin_hour == 1
    message = obj_day_sev
}

# Scoring function to determine severity level
scoring(score, critical_score, high_score, medium_score, low_score) := message if {
    score >= critical_score
    message = "critical"
} else := message if {
    score >= high_score
    score < critical_score
    message = "high"
} else := message if {
    score >= medium_score
    score < high_score
    message = "medium"
} else := message if {
    low_score != null
    score >= low_score
    score < medium_score
    message = "low"
} else := message if {
    low_score == null
    score < medium_score
    message = "low"
} else := message if {
    message = "unknown"
}

# High volume hour check
is_high_volume_hour(select_hour, select_day) if {
    select_hour == 1
    select_day == 1
} else := false