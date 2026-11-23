#line 371 "radvdump.c.878ca6b"
		case ND_OPT_ROUTE_INFORMATION: {
			struct nd_opt_route_info_local *rinfo = (struct nd_opt_route_info_local *)opt_str;

			if (optlen == 8) {
				printf("\n\troute ::/0\n\t{\n");
			} else {
				struct in6_addr addr;
				memset(&addr, 0, sizeof(addr));
				if (rinfo->nd_opt_ri_len > 1)
					memcpy(&addr, &rinfo->nd_opt_ri_prefix, (rinfo->nd_opt_ri_len - 1) * 8);
				addrtostr(&addr, prefix_str, sizeof(prefix_str));
				printf("\n\troute %s/%d\n\t{\n", prefix_str, rinfo->nd_opt_ri_prefix_len);
			}

			if (!edefs || (((radvert->nd_ra_flags_reserved & 0x18) >> 3) & 0xff) != DFLT_AdvRoutePreference) {
				printf("\t\tAdvRoutePreference ");
				print_preferences(((rinfo->nd_opt_ri_flags_reserved & 0x18) >> 3) & 0xff);
				printf(";\n");
			}

			/* XXX: we check DFLT_AdvRouteLifetime by interface, and it's outside of context here */
			if (ntohl(rinfo->nd_opt_ri_lifetime) == 0xffffffff)
				printf("\t\tAdvRouteLifetime infinity; # (0xffffffff)\n");
			else
				printf("\t\tAdvRouteLifetime %u;\n", ntohl(rinfo->nd_opt_ri_lifetime));

			printf("\t}; # End of route definition\n\n");
			break;
		}
