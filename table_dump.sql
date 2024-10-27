--
-- PostgreSQL database dump
--

-- Dumped from database version 15.1
-- Dumped by pg_dump version 15.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
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
-- Name: jwt_tokens; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.jwt_tokens (
    id integer NOT NULL,
    user_id integer NOT NULL,
    username character varying(255) NOT NULL,
    last_updated timestamp with time zone DEFAULT now() NOT NULL,
    number_update smallint DEFAULT 0 NOT NULL,
    jwt_token character varying(255) NOT NULL
);


ALTER TABLE public.jwt_tokens OWNER TO postgres;

--
-- Name: jwt_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.jwt_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.jwt_tokens_id_seq OWNER TO postgres;

--
-- Name: jwt_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.jwt_tokens_id_seq OWNED BY public.jwt_tokens.id;


--
-- Name: jwt_tokens id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.jwt_tokens ALTER COLUMN id SET DEFAULT nextval('public.jwt_tokens_id_seq'::regclass);


--
-- Data for Name: jwt_tokens; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.jwt_tokens (id, user_id, username, last_updated, number_update, jwt_token) FROM stdin;
13	49	Name78	2024-10-22 14:40:04.554817+01	3	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI0OSIsImlhdCI6MTcyOTYwNDUyMSwiZXhwIjoxNzI5NjkwOTIxfQ.Qf71xS1KgnkWq7b5BxZh48SW9MYPe9ATv-jvET4_rAw
14	56	Name87	2024-10-22 19:46:26.426212+01	0	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjU2LCJ1c2VybmFtZSI6Ik5hbWU4NyIsImlhdCI6MTcyOTYyMjc4NiwiZXhwIjoxNzI5NzA5MTg2fQ.MbaOXscrN4Jv-xAYXGaTRBMmGlgLIv0ySQDRiPoG2F0
7	41	Name67	2024-10-22 09:45:33.850928+01	1	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI0MSIsImlhdCI6MTcyOTU4Njk5NywiZXhwIjoxNzI5NTg3ODk3fQ.vYB7HxEQeCGNuOVAKIn7INYvj14xbcBV97wToAl6hEo
8	42	Name69	2024-10-22 09:57:41.623734+01	1	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI0MiIsImlhdCI6MTcyOTU4NzUzNywiZXhwIjoxNzI5NTg4NDM3fQ.Pa3p1jwluq1ZpcQfSdH-Iwzh5lbc6K9gtF0ke7xHVxI
15	57	Name88	2024-10-22 19:48:46.027319+01	6	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI1NyIsImlhdCI6MTcyOTY2MTc4NywiZXhwIjoxNzI5NzQ4MTg3fQ.as1TiMmMCV1LLezL6ciaVmb_JEHMYzN_5HIplWkrhg8
9	43	Name70	2024-10-22 13:17:02.273148+01	5	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI0MyIsImlhdCI6MTcyOTYwMTU4NywiZXhwIjoxODE2MDAxNTg3fQ.psHFF-65WFzPiSc7FIxEltP_O-gvNdh8f223ExBlVMY
16	58	Name90	2024-10-23 07:20:46.780771+01	2	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI1OCIsImlhdCI6MTcyOTY5MTY0NiwiZXhwIjoxNzI5Nzc4MDQ2fQ.CyjlfoqceRG2rk24Geblskl5-krA36wK2wtOesRZ1K0
17	59	Name91	2024-10-24 06:47:07.458399+01	0	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjU5LCJ1c2VybmFtZSI6Ik5hbWU5MSIsImlhdCI6MTcyOTc0ODgyNywiZXhwIjoxNzI5ODM1MjI3fQ.m80SxyG0RGMca7H1fYhowOmdLWd7MG-6IrNQWFY7bs0
10	46	Name73	2024-10-22 14:09:01.591446+01	3	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI0NiIsImlhdCI6MTcyOTYwMjk3NywiZXhwIjoxNzI5Njg5Mzc3fQ.qAODcuaq5qQu2tizc1tI4ARrJ1A6frOQnMUgmgFa7XQ
11	47	Name75	2024-10-22 14:28:43.389556+01	2	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI0NyIsImlhdCI6MTcyOTYwMzk1MywiZXhwIjoxNzI5NjkwMzUzfQ.UrrPli2wm2RDgVMMxkQRelA6oQkk2YGkJXFj9IKmCJI
12	48	Name77	2024-10-22 14:37:01.584287+01	1	eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI0OCIsImlhdCI6MTcyOTYwNDI0NywiZXhwIjoxNzI5NjkwNjQ3fQ.n4DoJr42_7ajqecn7T64nnw-rumz1egJptKbetUbCMA
\.


--
-- Name: jwt_tokens_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.jwt_tokens_id_seq', 17, true);


--
-- Name: jwt_tokens jwt_token_user_id; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.jwt_tokens
    ADD CONSTRAINT jwt_token_user_id UNIQUE (user_id);


--
-- Name: jwt_tokens jwt_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.jwt_tokens
    ADD CONSTRAINT jwt_tokens_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

