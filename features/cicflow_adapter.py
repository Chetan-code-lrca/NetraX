MODEL_TO_CIC = {
    " Destination Port": "dst_port",
    " Flow Duration": "flow_duration",
    " Total Fwd Packets": "tot_fwd_pkts",
    "Total Length of Fwd Packets": "totlen_fwd_pkts",
    " Fwd Packet Length Max": "fwd_pkt_len_max",
    " Fwd Packet Length Min": "fwd_pkt_len_min",
    " Fwd Packet Length Mean": "fwd_pkt_len_mean",
    " Fwd IAT Mean": "fwd_iat_mean",
    " Fwd IAT Std": "fwd_iat_std",
    " Fwd IAT Max": "fwd_iat_max",
    " Fwd IAT Min": "fwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    " Fwd URG Flags": "fwd_urg_flags",
    " Fwd Header Length": "fwd_header_len",
    "Fwd Packets/s": "fwd_pkts_s",
    " SYN Flag Count": "syn_flag_cnt",
    " RST Flag Count": "rst_flag_cnt",
    " PSH Flag Count": "psh_flag_cnt",
    " ACK Flag Count": "ack_flag_cnt",
    " URG Flag Count": "urg_flag_cnt",
    " CWE Flag Count": "cwr_flag_count",
    " ECE Flag Count": "ece_flag_cnt",
    " Avg Fwd Segment Size": "fwd_seg_size_avg",
    " Fwd Avg Packets/Bulk": "fwd_pkts_b_avg",
    " Fwd Avg Bulk Rate": "fwd_blk_rate_avg",
    "Subflow Fwd Packets": "subflow_fwd_pkts",
    "Init_Win_bytes_forward": "init_fwd_win_byts",
    " act_data_pkt_fwd": "fwd_act_data_pkts",
    " min_seg_size_forward": "fwd_seg_size_min",
}


def adapt_cicflow_row(row, feature_names):
    """
    Convert one CICFlowMeter row into the exact feature
    dictionary expected by a trained NetraX model.
    """

    features = {}

    for model_feature in feature_names:
        cic_feature = MODEL_TO_CIC.get(model_feature)

        if cic_feature is None:
            raise KeyError(
                f"No CICFlowMeter mapping for {model_feature!r}"
            )

        if cic_feature not in row:
            raise KeyError(
                f"CICFlowMeter column missing: {cic_feature!r}"
            )

        features[model_feature] = row[cic_feature]

    return features
