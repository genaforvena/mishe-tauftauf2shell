int dpi_sig_bld(dpi_dlpbld_t *dlpsig, int flag)
{
    int i,j,k;
    char dlpsig_buf[MAX_USER_SIG_LEN];
    int len = 0;
    int len1 =0;
    static dpi_detector_t *dlpDetector = NULL;
    DEBUG_DLP("# of macs: (%d), # of delete macs: (%d), # of dlp rules: (%d) flag 0x%x\n",
               dlpsig->num_macs, dlpsig->num_del_macs, dlpsig->num_dlp_rules, flag);

    if (flag & MSG_START) {
       if (dlpDetector) {
           DEBUG_ERROR(DBG_DETECT, "old DLP DETECTOR %p exists!\n", dlpDetector);
           dpi_dlp_detector_destroy(dlpDetector);
           dlpDetector = NULL;
       }
    } else {
        if (!dlpDetector) {
            DEBUG_ERROR(DBG_DETECT, "missed dlp msg start!\n");
            return -1;
        }
    }

    if (flag & MSG_START) {
        dlpDetector = dpi_dlp_detector_init(dlpsig->apply_dir);
        if (!dlpDetector) {
            return -1;
        }
        dlpDetector->dlp_ver = GET_NEW_DLP_DETECTOR_VER();
        memset(&dlpDetector->dlp_pcre_hs_summary, 0, sizeof(dpi_hs_summary_t));
    }
    //build SigList for updated dlp rules
    for (j = 0; j < dlpsig->num_dlp_rules; j ++) {
        len = sprintf(dlpsig_buf, 
            "name %s;"
            "sig_id %u;",
            dlpsig->dlp_rule_list[j].rulename,
            dlpsig->dlp_rule_list[j].sigid
            );
        for (k = 0; k < dlpsig->dlp_rule_list[j].num_dlp_rule_pats; k ++) {
            len1 = sprintf(&dlpsig_buf[len], "pcre %s;",
                dlpsig->dlp_rule_list[j].dlp_rule_pat_list[k].rule_pattern);
                len += len1;
        }
        dlpsig_buf[len]='\0';
        //parse each dlp rule and store into SigList
        dpi_dlp_proc(dlpsig_buf, (void *)dlpDetector);
    }
    
    if (flag & MSG_END) {
        DEBUG_DLP("PARSE DLP RULE DONE!\n");
        DEBUG_DLP("Single pattern subtotal: hyperscan db_count(%u) allocated, db_bytes(%u), scratch_size(%u)!\n",
            dlpDetector->dlp_pcre_hs_summary.db_count, dlpDetector->dlp_pcre_hs_summary.db_bytes, dlpDetector->dlp_pcre_hs_summary.scratch_size);
        //dpi_print_siglist(dlpDetector);
    }

    if (!(flag & MSG_END)) {
        return 0;
    }
    if (dlpsig->num_dlp_rules == 0) {
        //there is no new dlp rules to build detect tree
        //thus release all old detector
        for (i = 0; i < dlpsig->num_macs; i++) {
            dpi_dlp_detect_release(&dlpsig->mac_list[i]);
        }
    } else {
        //after we parse all the dlp rules into SigList
        //we need to build detect tree
        for (i = 0; i < dlpsig->num_macs; i++) {
            dpi_dlp_detect_update(&dlpsig->mac_list[i], dlpDetector);
        }
    }
    //some of the ep no longer need dlp service
    for (i = 0; i < dlpsig->num_del_macs; i++) {
        dpi_dlp_detect_release(&dlpsig->del_mac_list[i]);
    }
    if (dlpDetector) {
        DEBUG_DLP("dlpDetector(%p) dlp_ref_cnt(%d) \n", dlpDetector, dlpDetector->dlp_ref_cnt);
    }
    if (dlpDetector && dlpDetector->dlp_ref_cnt == 0) {
        dpi_dlp_detector_destroy(dlpDetector);
    } else if (dlpDetector && dlpDetector->dlp_ref_cnt > 0) {
        dp_dlp_build_detector(dlpDetector);
    }

    dlpDetector = NULL;
    return 0;
}
