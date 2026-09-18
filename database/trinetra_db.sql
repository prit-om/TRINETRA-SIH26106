--
-- PostgreSQL database dump
--

\restrict 7BbQM4Gvlj2StdyK4U5VySBwtR58LRnnOqdsOWrF5hfDVV6Gk4y7aiuKn1G5dC9

-- Dumped from database version 18.6
-- Dumped by pg_dump version 18.6

-- Started on 2026-09-13 18:23:31

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 225 (class 1259 OID 24663)
-- Name: attachment_findings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.attachment_findings (
    id bigint NOT NULL,
    case_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    filename character varying(255) NOT NULL,
    file_type character varying(100) NOT NULL,
    file_hash_sha256 character varying(64) NOT NULL,
    hash_reputation_flagged boolean DEFAULT false NOT NULL,
    file_size_bytes bigint
);


ALTER TABLE public.attachment_findings OWNER TO postgres;

--
-- TOC entry 224 (class 1259 OID 24662)
-- Name: attachment_findings_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.attachment_findings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.attachment_findings_id_seq OWNER TO postgres;

--
-- TOC entry 5131 (class 0 OID 0)
-- Dependencies: 224
-- Name: attachment_findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.attachment_findings_id_seq OWNED BY public.attachment_findings.id;


--
-- TOC entry 229 (class 1259 OID 24712)
-- Name: case_correlation; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.case_correlation (
    id bigint NOT NULL,
    case_id_a uuid NOT NULL,
    case_id_b uuid NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    shared_indicator_type character varying(30) NOT NULL,
    shared_indicator_value character varying(500) NOT NULL,
    correlation_confidence double precision NOT NULL,
    CONSTRAINT case_correlation_correlation_confidence_check CHECK (((correlation_confidence >= (0)::double precision) AND (correlation_confidence <= (1)::double precision))),
    CONSTRAINT case_correlation_shared_indicator_type_check CHECK (((shared_indicator_type)::text = ANY ((ARRAY['domain'::character varying, 'ip'::character varying, 'url'::character varying, 'attachment_hash'::character varying, 'sender_email'::character varying])::text[]))),
    CONSTRAINT different_cases CHECK ((case_id_a <> case_id_b))
);


ALTER TABLE public.case_correlation OWNER TO postgres;

--
-- TOC entry 228 (class 1259 OID 24711)
-- Name: case_correlation_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.case_correlation_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.case_correlation_id_seq OWNER TO postgres;

--
-- TOC entry 5132 (class 0 OID 0)
-- Dependencies: 228
-- Name: case_correlation_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.case_correlation_id_seq OWNED BY public.case_correlation.id;


--
-- TOC entry 219 (class 1259 OID 24576)
-- Name: cases; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.cases (
    case_id uuid NOT NULL,
    uploaded_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    original_filename character varying(255),
    sender_email character varying(255) NOT NULL,
    sender_display_name character varying(255),
    reply_to character varying(255),
    subject text NOT NULL,
    body_hash character varying(64) NOT NULL,
    raw_email_ref text,
    risk_score integer NOT NULL,
    classification character varying(20) NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    analyst_feedback character varying(20),
    CONSTRAINT cases_analyst_feedback_check CHECK (((analyst_feedback)::text = ANY ((ARRAY['safe'::character varying, 'phishing'::character varying, 'unmarked'::character varying])::text[]))),
    CONSTRAINT cases_classification_check CHECK (((classification)::text = ANY ((ARRAY['Safe'::character varying, 'Low Risk'::character varying, 'Suspicious'::character varying, 'Phishing'::character varying, 'Critical'::character varying])::text[]))),
    CONSTRAINT cases_risk_score_check CHECK (((risk_score >= 0) AND (risk_score <= 100))),
    CONSTRAINT cases_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'analyzed'::character varying, 'reviewed'::character varying, 'closed'::character varying])::text[])))
);


ALTER TABLE public.cases OWNER TO postgres;

--
-- TOC entry 227 (class 1259 OID 24684)
-- Name: geolocation; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.geolocation (
    id bigint NOT NULL,
    case_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    earliest_external_ip character varying(45) NOT NULL,
    country character varying(100) NOT NULL,
    region character varying(100),
    city character varying(100),
    latitude double precision,
    longitude double precision,
    isp character varying(255),
    asn character varying(100),
    is_vpn_or_proxy boolean DEFAULT false NOT NULL,
    is_tor_exit_node boolean DEFAULT false NOT NULL,
    confidence_level double precision NOT NULL,
    CONSTRAINT geolocation_confidence_level_check CHECK (((confidence_level >= (0)::double precision) AND (confidence_level <= (1)::double precision)))
);


ALTER TABLE public.geolocation OWNER TO postgres;

--
-- TOC entry 226 (class 1259 OID 24683)
-- Name: geolocation_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.geolocation_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.geolocation_id_seq OWNER TO postgres;

--
-- TOC entry 5133 (class 0 OID 0)
-- Dependencies: 226
-- Name: geolocation_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.geolocation_id_seq OWNED BY public.geolocation.id;


--
-- TOC entry 231 (class 1259 OID 32769)
-- Name: header_analysis; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.header_analysis (
    id bigint NOT NULL,
    case_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    spf_result character varying(10) NOT NULL,
    dkim_result character varying(10) NOT NULL,
    dmarc_result character varying(10) NOT NULL,
    sender_returnpath_mismatch boolean DEFAULT false NOT NULL,
    replyto_anomaly boolean DEFAULT false NOT NULL,
    relay_hop_count integer DEFAULT 0 NOT NULL,
    received_chain_raw text,
    header_anomaly_score double precision NOT NULL,
    CONSTRAINT header_analysis_dkim_result_check CHECK (((dkim_result)::text = ANY ((ARRAY['pass'::character varying, 'fail'::character varying, 'none'::character varying])::text[]))),
    CONSTRAINT header_analysis_dmarc_result_check CHECK (((dmarc_result)::text = ANY ((ARRAY['pass'::character varying, 'fail'::character varying, 'none'::character varying])::text[]))),
    CONSTRAINT header_analysis_header_anomaly_score_check CHECK (((header_anomaly_score >= (0)::double precision) AND (header_anomaly_score <= (1)::double precision))),
    CONSTRAINT header_analysis_spf_result_check CHECK (((spf_result)::text = ANY ((ARRAY['pass'::character varying, 'fail'::character varying, 'neutral'::character varying, 'none'::character varying])::text[])))
);


ALTER TABLE public.header_analysis OWNER TO postgres;

--
-- TOC entry 230 (class 1259 OID 32768)
-- Name: header_analysis_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.header_analysis_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.header_analysis_id_seq OWNER TO postgres;

--
-- TOC entry 5134 (class 0 OID 0)
-- Dependencies: 230
-- Name: header_analysis_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.header_analysis_id_seq OWNED BY public.header_analysis.id;


--
-- TOC entry 221 (class 1259 OID 24600)
-- Name: nlp_analysis; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.nlp_analysis (
    id bigint NOT NULL,
    case_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    executive_impersonation_score double precision NOT NULL,
    urgent_request_score double precision NOT NULL,
    financial_request_score double precision NOT NULL,
    social_engineering_score double precision NOT NULL,
    credential_harvesting_score double precision NOT NULL,
    ai_generated_text_likelihood double precision NOT NULL,
    overall_phishing_probability double precision NOT NULL,
    model_reasoning text,
    model_used character varying(255),
    CONSTRAINT nlp_analysis_ai_generated_text_likelihood_check CHECK (((ai_generated_text_likelihood >= (0)::double precision) AND (ai_generated_text_likelihood <= (1)::double precision))),
    CONSTRAINT nlp_analysis_credential_harvesting_score_check CHECK (((credential_harvesting_score >= (0)::double precision) AND (credential_harvesting_score <= (1)::double precision))),
    CONSTRAINT nlp_analysis_executive_impersonation_score_check CHECK (((executive_impersonation_score >= (0)::double precision) AND (executive_impersonation_score <= (1)::double precision))),
    CONSTRAINT nlp_analysis_financial_request_score_check CHECK (((financial_request_score >= (0)::double precision) AND (financial_request_score <= (1)::double precision))),
    CONSTRAINT nlp_analysis_overall_phishing_probability_check CHECK (((overall_phishing_probability >= (0)::double precision) AND (overall_phishing_probability <= (1)::double precision))),
    CONSTRAINT nlp_analysis_social_engineering_score_check CHECK (((social_engineering_score >= (0)::double precision) AND (social_engineering_score <= (1)::double precision))),
    CONSTRAINT nlp_analysis_urgent_request_score_check CHECK (((urgent_request_score >= (0)::double precision) AND (urgent_request_score <= (1)::double precision)))
);


ALTER TABLE public.nlp_analysis OWNER TO postgres;

--
-- TOC entry 220 (class 1259 OID 24599)
-- Name: nlp_analysis_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.nlp_analysis_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.nlp_analysis_id_seq OWNER TO postgres;

--
-- TOC entry 5135 (class 0 OID 0)
-- Dependencies: 220
-- Name: nlp_analysis_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.nlp_analysis_id_seq OWNED BY public.nlp_analysis.id;


--
-- TOC entry 223 (class 1259 OID 24635)
-- Name: url_findings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.url_findings (
    id bigint NOT NULL,
    case_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    original_url text NOT NULL,
    expanded_url text,
    domain character varying(255) NOT NULL,
    is_shortened boolean DEFAULT false NOT NULL,
    reputation_source character varying(255),
    is_malicious boolean DEFAULT false NOT NULL,
    is_lookalike_domain boolean DEFAULT false NOT NULL,
    redirect_chain_length integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.url_findings OWNER TO postgres;

--
-- TOC entry 222 (class 1259 OID 24634)
-- Name: url_findings_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.url_findings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.url_findings_id_seq OWNER TO postgres;

--
-- TOC entry 5136 (class 0 OID 0)
-- Dependencies: 222
-- Name: url_findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.url_findings_id_seq OWNED BY public.url_findings.id;


--
-- TOC entry 4896 (class 2604 OID 24666)
-- Name: attachment_findings id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.attachment_findings ALTER COLUMN id SET DEFAULT nextval('public.attachment_findings_id_seq'::regclass);


--
-- TOC entry 4903 (class 2604 OID 24715)
-- Name: case_correlation id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.case_correlation ALTER COLUMN id SET DEFAULT nextval('public.case_correlation_id_seq'::regclass);


--
-- TOC entry 4899 (class 2604 OID 24687)
-- Name: geolocation id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.geolocation ALTER COLUMN id SET DEFAULT nextval('public.geolocation_id_seq'::regclass);


--
-- TOC entry 4905 (class 2604 OID 32772)
-- Name: header_analysis id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.header_analysis ALTER COLUMN id SET DEFAULT nextval('public.header_analysis_id_seq'::regclass);


--
-- TOC entry 4888 (class 2604 OID 24603)
-- Name: nlp_analysis id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.nlp_analysis ALTER COLUMN id SET DEFAULT nextval('public.nlp_analysis_id_seq'::regclass);


--
-- TOC entry 4890 (class 2604 OID 24638)
-- Name: url_findings id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.url_findings ALTER COLUMN id SET DEFAULT nextval('public.url_findings_id_seq'::regclass);


--
-- TOC entry 5119 (class 0 OID 24663)
-- Dependencies: 225
-- Data for Name: attachment_findings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.attachment_findings (id, case_id, created_at, filename, file_type, file_hash_sha256, hash_reputation_flagged, file_size_bytes) FROM stdin;
1	11111111-1111-1111-1111-111111111111	2026-09-13 11:40:20.115951+05:30	class_schedule.pdf	application/pdf	dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd	f	245760
2	22222222-2222-2222-2222-222222222222	2026-09-13 11:40:20.115951+05:30	account_verification.html	text/html	eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee	t	18432
3	33333333-3333-3333-3333-333333333333	2026-09-13 11:40:20.115951+05:30	payment_details.xlsx	application/vnd.openxmlformats-officedocument.spreadsheetml.sheet	ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff	f	98304
\.


--
-- TOC entry 5123 (class 0 OID 24712)
-- Dependencies: 229
-- Data for Name: case_correlation; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.case_correlation (id, case_id_a, case_id_b, created_at, shared_indicator_type, shared_indicator_value, correlation_confidence) FROM stdin;
1	22222222-2222-2222-2222-222222222222	33333333-3333-3333-3333-333333333333	2026-09-13 11:41:56.083322+05:30	domain	example-suspicious-domain.com	0.86
\.


--
-- TOC entry 5113 (class 0 OID 24576)
-- Dependencies: 219
-- Data for Name: cases; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.cases (case_id, uploaded_at, created_at, original_filename, sender_email, sender_display_name, reply_to, subject, body_hash, raw_email_ref, risk_score, classification, status, analyst_feedback) FROM stdin;
11111111-1111-1111-1111-111111111111	2026-09-13 11:24:11.918637+05:30	2026-09-13 11:24:11.918637+05:30	sample_safe.eml	student@college.edu	College Student	\N	Class schedule update	aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa	\N	10	Safe	analyzed	safe
22222222-2222-2222-2222-222222222222	2026-09-13 11:24:11.918637+05:30	2026-09-13 11:24:11.918637+05:30	sample_phishing.eml	security-alert@example.com	Security Team	verify@example.com	Urgent account verification required	bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb	\N	91	Phishing	analyzed	unmarked
33333333-3333-3333-3333-333333333333	2026-09-13 11:24:11.918637+05:30	2026-09-13 11:24:11.918637+05:30	sample_suspicious.eml	finance@example.net	Finance Department	\N	Payment request	cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc	\N	72	Suspicious	pending	unmarked
\.


--
-- TOC entry 5121 (class 0 OID 24684)
-- Dependencies: 227
-- Data for Name: geolocation; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.geolocation (id, case_id, created_at, earliest_external_ip, country, region, city, latitude, longitude, isp, asn, is_vpn_or_proxy, is_tor_exit_node, confidence_level) FROM stdin;
1	11111111-1111-1111-1111-111111111111	2026-09-13 11:41:17.176883+05:30	192.0.2.10	India	West Bengal	Kolkata	22.5726	88.3639	Example ISP	AS64500	f	f	0.95
2	22222222-2222-2222-2222-222222222222	2026-09-13 11:41:17.176883+05:30	198.51.100.20	United States	California	Los Angeles	34.0522	-118.2437	Example Hosting Provider	AS64501	t	f	0.72
3	33333333-3333-3333-3333-333333333333	2026-09-13 11:41:17.176883+05:30	203.0.113.10	Singapore	\N	Singapore	1.3521	103.8198	Example Network	AS64502	f	f	0.8
\.


--
-- TOC entry 5125 (class 0 OID 32769)
-- Dependencies: 231
-- Data for Name: header_analysis; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.header_analysis (id, case_id, created_at, spf_result, dkim_result, dmarc_result, sender_returnpath_mismatch, replyto_anomaly, relay_hop_count, received_chain_raw, header_anomaly_score) FROM stdin;
1	11111111-1111-1111-1111-111111111111	2026-09-13 11:36:33.725803+05:30	pass	pass	pass	f	f	3	[{"hop":1,"ip":"192.0.2.10"}]	0.05
2	22222222-2222-2222-2222-222222222222	2026-09-13 11:36:33.725803+05:30	fail	fail	fail	t	t	6	[{"hop":1,"ip":"198.51.100.20"},{"hop":2,"ip":"198.51.100.30"}]	0.92
3	33333333-3333-3333-3333-333333333333	2026-09-13 11:36:33.725803+05:30	neutral	pass	none	f	t	4	[{"hop":1,"ip":"203.0.113.10"}]	0.48
\.


--
-- TOC entry 5115 (class 0 OID 24600)
-- Dependencies: 221
-- Data for Name: nlp_analysis; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.nlp_analysis (id, case_id, created_at, executive_impersonation_score, urgent_request_score, financial_request_score, social_engineering_score, credential_harvesting_score, ai_generated_text_likelihood, overall_phishing_probability, model_reasoning, model_used) FROM stdin;
1	11111111-1111-1111-1111-111111111111	2026-09-13 11:37:47.695608+05:30	0.02	0.03	0.01	0.02	0.01	0.1	0.03	Normal informational email with no significant phishing indicators.	TRINETRA-NLP-v1
2	22222222-2222-2222-2222-222222222222	2026-09-13 11:37:47.695608+05:30	0.91	0.95	0.88	0.94	0.9	0.76	0.93	Urgent language, impersonation indicators and credential-related request detected.	TRINETRA-NLP-v1
3	33333333-3333-3333-3333-333333333333	2026-09-13 11:37:47.695608+05:30	0.35	0.62	0.71	0.55	0.28	0.42	0.68	Financial request and moderately urgent language detected; further investigation recommended.	TRINETRA-NLP-v1
\.


--
-- TOC entry 5117 (class 0 OID 24635)
-- Dependencies: 223
-- Data for Name: url_findings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.url_findings (id, case_id, created_at, original_url, expanded_url, domain, is_shortened, reputation_source, is_malicious, is_lookalike_domain, redirect_chain_length) FROM stdin;
1	11111111-1111-1111-1111-111111111111	2026-09-13 11:39:33.562474+05:30	https://college.edu/notice	https://college.edu/notice	college.edu	f	TRINETRA	f	f	0
2	22222222-2222-2222-2222-222222222222	2026-09-13 11:39:33.562474+05:30	https://bit.ly/account-check	https://secure-account-example.com/login	secure-account-example.com	t	TRINETRA	t	t	2
3	33333333-3333-3333-3333-333333333333	2026-09-13 11:39:33.562474+05:30	https://finance-example.net/payment	https://finance-example.net/payment	finance-example.net	f	TRINETRA	f	t	1
\.


--
-- TOC entry 5137 (class 0 OID 0)
-- Dependencies: 224
-- Name: attachment_findings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.attachment_findings_id_seq', 3, true);


--
-- TOC entry 5138 (class 0 OID 0)
-- Dependencies: 228
-- Name: case_correlation_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.case_correlation_id_seq', 1, true);


--
-- TOC entry 5139 (class 0 OID 0)
-- Dependencies: 226
-- Name: geolocation_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.geolocation_id_seq', 3, true);


--
-- TOC entry 5140 (class 0 OID 0)
-- Dependencies: 230
-- Name: header_analysis_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.header_analysis_id_seq', 3, true);


--
-- TOC entry 5141 (class 0 OID 0)
-- Dependencies: 220
-- Name: nlp_analysis_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.nlp_analysis_id_seq', 3, true);


--
-- TOC entry 5142 (class 0 OID 0)
-- Dependencies: 222
-- Name: url_findings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.url_findings_id_seq', 3, true);


--
-- TOC entry 4943 (class 2606 OID 24677)
-- Name: attachment_findings attachment_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.attachment_findings
    ADD CONSTRAINT attachment_findings_pkey PRIMARY KEY (id);


--
-- TOC entry 4951 (class 2606 OID 24730)
-- Name: case_correlation case_correlation_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.case_correlation
    ADD CONSTRAINT case_correlation_pkey PRIMARY KEY (id);


--
-- TOC entry 4930 (class 2606 OID 24598)
-- Name: cases cases_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cases
    ADD CONSTRAINT cases_pkey PRIMARY KEY (case_id);


--
-- TOC entry 4946 (class 2606 OID 24705)
-- Name: geolocation geolocation_case_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.geolocation
    ADD CONSTRAINT geolocation_case_id_key UNIQUE (case_id);


--
-- TOC entry 4948 (class 2606 OID 24703)
-- Name: geolocation geolocation_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.geolocation
    ADD CONSTRAINT geolocation_pkey PRIMARY KEY (id);


--
-- TOC entry 4956 (class 2606 OID 32796)
-- Name: header_analysis header_analysis_case_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.header_analysis
    ADD CONSTRAINT header_analysis_case_id_key UNIQUE (case_id);


--
-- TOC entry 4958 (class 2606 OID 32794)
-- Name: header_analysis header_analysis_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.header_analysis
    ADD CONSTRAINT header_analysis_pkey PRIMARY KEY (id);


--
-- TOC entry 4935 (class 2606 OID 24627)
-- Name: nlp_analysis nlp_analysis_case_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.nlp_analysis
    ADD CONSTRAINT nlp_analysis_case_id_key UNIQUE (case_id);


--
-- TOC entry 4937 (class 2606 OID 24625)
-- Name: nlp_analysis nlp_analysis_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.nlp_analysis
    ADD CONSTRAINT nlp_analysis_pkey PRIMARY KEY (id);


--
-- TOC entry 4941 (class 2606 OID 24656)
-- Name: url_findings url_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.url_findings
    ADD CONSTRAINT url_findings_pkey PRIMARY KEY (id);


--
-- TOC entry 4944 (class 1259 OID 24746)
-- Name: idx_attachment_findings_case_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_attachment_findings_case_id ON public.attachment_findings USING btree (case_id);


--
-- TOC entry 4952 (class 1259 OID 24748)
-- Name: idx_case_correlation_case_a; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_case_correlation_case_a ON public.case_correlation USING btree (case_id_a);


--
-- TOC entry 4953 (class 1259 OID 24749)
-- Name: idx_case_correlation_case_b; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_case_correlation_case_b ON public.case_correlation USING btree (case_id_b);


--
-- TOC entry 4954 (class 1259 OID 24750)
-- Name: idx_case_correlation_indicator; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_case_correlation_indicator ON public.case_correlation USING btree (shared_indicator_value);


--
-- TOC entry 4931 (class 1259 OID 24742)
-- Name: idx_cases_classification; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cases_classification ON public.cases USING btree (classification);


--
-- TOC entry 4932 (class 1259 OID 24741)
-- Name: idx_cases_sender_email; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cases_sender_email ON public.cases USING btree (sender_email);


--
-- TOC entry 4933 (class 1259 OID 24743)
-- Name: idx_cases_uploaded_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cases_uploaded_at ON public.cases USING btree (uploaded_at);


--
-- TOC entry 4949 (class 1259 OID 24747)
-- Name: idx_geolocation_case_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_geolocation_case_id ON public.geolocation USING btree (case_id);


--
-- TOC entry 4938 (class 1259 OID 24744)
-- Name: idx_url_findings_case_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_url_findings_case_id ON public.url_findings USING btree (case_id);


--
-- TOC entry 4939 (class 1259 OID 24745)
-- Name: idx_url_findings_domain; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_url_findings_domain ON public.url_findings USING btree (domain);


--
-- TOC entry 4961 (class 2606 OID 24678)
-- Name: attachment_findings fk_attachment_case; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.attachment_findings
    ADD CONSTRAINT fk_attachment_case FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- TOC entry 4963 (class 2606 OID 24731)
-- Name: case_correlation fk_correlation_case_a; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.case_correlation
    ADD CONSTRAINT fk_correlation_case_a FOREIGN KEY (case_id_a) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- TOC entry 4964 (class 2606 OID 24736)
-- Name: case_correlation fk_correlation_case_b; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.case_correlation
    ADD CONSTRAINT fk_correlation_case_b FOREIGN KEY (case_id_b) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- TOC entry 4962 (class 2606 OID 24706)
-- Name: geolocation fk_geolocation_case; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.geolocation
    ADD CONSTRAINT fk_geolocation_case FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- TOC entry 4965 (class 2606 OID 32797)
-- Name: header_analysis fk_header_case; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.header_analysis
    ADD CONSTRAINT fk_header_case FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- TOC entry 4959 (class 2606 OID 24628)
-- Name: nlp_analysis fk_nlp_case; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.nlp_analysis
    ADD CONSTRAINT fk_nlp_case FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


--
-- TOC entry 4960 (class 2606 OID 24657)
-- Name: url_findings fk_url_case; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.url_findings
    ADD CONSTRAINT fk_url_case FOREIGN KEY (case_id) REFERENCES public.cases(case_id) ON DELETE CASCADE;


-- Completed on 2026-09-13 18:23:31

--
-- PostgreSQL database dump complete
--

\unrestrict 7BbQM4Gvlj2StdyK4U5VySBwtR58LRnnOqdsOWrF5hfDVV6Gk4y7aiuKn1G5dC9

