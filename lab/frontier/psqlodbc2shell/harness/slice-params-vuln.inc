static int
processParameters(QueryParse *qp, QueryBuild *qb,
		size_t *output_count, SQLLEN param_pos[][2])
{
	int retval, innerParenthesis, param_count;
	BOOL stop;

	/* begin with outer '(' */
	innerParenthesis = 0;
	param_count = 0;
	if (NULL != output_count)
		*output_count = 0;
	stop = FALSE;
	for (; F_OldPos(qp) < qp->stmt_len; F_OldNext(qp))
	{
		retval = inner_process_tokens(qp, qb);
		if (retval == SQL_ERROR)
			return retval;
		if (MBCS_NON_ASCII(qp->encstr))
			continue;
		if (!QP_in_idle_status(qp))
			continue;

		switch (F_OldChar(qp))
		{
			case ',':
				if (1 == innerParenthesis)
				{
					param_pos[param_count][1] = F_NewPos(qb) - 2;
					param_count++;
					param_pos[param_count][0] = F_NewPos(qb);
					param_pos[param_count][1] = -1;
				}
				break;
			case '(':
				if (0 == innerParenthesis)
				{
					param_pos[param_count][0] = F_NewPos(qb);
					param_pos[param_count][1] = -1;
				}
				innerParenthesis++;
				break;

			case ')':
				innerParenthesis--;
				if (0 == innerParenthesis)
				{
					param_pos[param_count][1] = F_NewPos(qb) - 2;
					param_count++;
					param_pos[param_count][0] =
					param_pos[param_count][1] = -1;
				}
				if (output_count)
					*output_count = F_NewPos(qb);
				break;

			case ODBC_ESCAPE_END:
				stop = (0 == innerParenthesis);
				break;

		}
		if (stop) /* returns with the last } position */
			break;
	}
	if (param_pos[param_count][0] >= 0)
	{
		MYLOG(0, "closing ) not found %d\n", innerParenthesis);
		qb->errornumber = STMT_EXEC_ERROR;
		qb->errormsg = "processParameters closing ) not found";
		return SQL_ERROR;
	}
	else if (1 == param_count) /* the 1 parameter is really valid ? */
	{
		BOOL	param_exist = FALSE;
		SQLLEN	i;

		for (i = param_pos[0][0]; i <= param_pos[0][1]; i++)
		{
			if (IS_NOT_SPACE(qb->query_statement[i]))
			{
				param_exist = TRUE;
				break;
			}
		}
		if (!param_exist)
		{
			param_pos[0][0] = param_pos[0][1] = -1;
		}
	}

	return SQL_SUCCESS;
}
