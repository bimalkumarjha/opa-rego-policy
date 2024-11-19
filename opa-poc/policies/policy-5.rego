package policies

import rego.v1



#5 ------------------- High Data Manipulation--------------------------

severity := "High Data Manipulation - HIGH" if {
	mandatory_features_high
	input.outlier_max_score_summary_hour >= 0.8
	input.is_admin_hour == 1
	input.sensitive_obj_hour >= 0.8
	input.sensitive_obj_day >= 0.6
} else := "High Data Manipulation - MEDIUM" if {
    mandatory_features_medium
	input.outlier_max_score_summary_hour >= 0.6
    input.outlier_max_score_summary_hour < 0.8
	input.is_admin_hour == 1
	input.sensitive_obj_hour >= 0.6
    input.sensitive_obj_hour < 0.8
	input.sensitive_obj_day >= 0.3
    input.sensitive_obj_day < 0.6
    not mandatory_features_high
} else := "High Data Manipulation - LOW" if {
    mandatory_features_low
	input.outlier_max_score_summary_hour >= 0.3
    input.outlier_max_score_summary_hour < 0.6
	input.is_admin_hour == 1
	input.sensitive_obj_hour >= 0.3
    input.sensitive_obj_hour < 0.6
    input.sensitive_obj_day < 0.3
    not mandatory_features_high
    not mandatory_features_medium
}

# Helper functions for OR logic

# Mandatory Features - High
mandatory_features_high if {
    input.count_dml_hour >= 0.8
}

mandatory_features_high if {
    high_volume
}

# Mandatory Features - Medium
mandatory_features_medium if {
    input.count_dml_hour >= 0.6
    input.count_dml_hour < 0.8
}

mandatory_features_medium if {
    high_volume
}

# Mandatory Features - Low
mandatory_features_low if {
    input.count_dml_hour >= 0.3
    input.count_dml_hour < 0.6
}

mandatory_features_low if {
    high_volume
}

# High Volume
high_volume if {
	input.is_high_volume_delete_hour == 1
	input.is_high_volume_delete_day == 1
}

high_volume if {
	input.is_high_volume_dml_hour == 1
	input.is_high_volume_dml_day == 1
}

high_volume if {
	input.is_high_volume_alter_hour == 1
	input.is_high_volume_alter_day == 1
}

high_volume if {
	input.is_high_volume_drop_hour == 1
	input.is_high_volume_drop_day == 1
}

high_volume if {
	input.is_high_volume_schema_element_rm_hour == 1
	input.is_high_volume_schema_element_rm_day == 1
}
