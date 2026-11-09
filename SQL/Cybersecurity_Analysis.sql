
/*
========================================================
PROJECT: CYBERSECURITY ANALYTICS
DATABASE: Oracle Database 21c XE
TABLE: CYBER1
RECORDS: 100,000
AUTHOR: Srinithya

DESCRIPTION:
SQL analysis of cybersecurity incident records.
========================================================
*/


-- ==========================================
-- SECTION 1: BASIC DATA VALIDATION
-- ==========================================

-- 1. Check total number of records

SELECT COUNT(*) AS TOTAL_INCIDENTS
FROM CYBER1;


-- 2. Display sample records

SELECT *
FROM CYBER1
WHERE ROWNUM <= 5;


-- ==========================================
-- SECTION 2: BASIC DATA ANALYSIS
-- ==========================================

-- 3. Calculate average attack severity

SELECT ROUND(AVG(ATTACK_SEVERITY), 2) AS AVG_SEVERITY
FROM CYBER1;


-- 4. Calculate average response time

SELECT ROUND(AVG(RESPONSE_TIME_MIN), 2) AS AVG_RESPONSE_TIME
FROM CYBER1;


-- 5. Count incidents by outcome

SELECT OUTCOME, COUNT(*) AS INCIDENT_COUNT
FROM CYBER1
GROUP BY OUTCOME;


-- 6. Identify high-severity incidents

SELECT COUNT(*) AS HIGH_SEVERITY_INCIDENTS
FROM CYBER1
WHERE ATTACK_SEVERITY >= 8;


-- ==========================================
-- SECTION 3: ATTACK TYPE ANALYSIS
-- ==========================================

-- 7. Count attacks by attack type

SELECT ATTACK_TYPE,
       COUNT(*) AS TOTAL_ATTACKS
FROM CYBER1
GROUP BY ATTACK_TYPE
ORDER BY TOTAL_ATTACKS DESC;

-- ==========================================
-- SECTION 4: ATTACK TYPE INVESTIGATION
-- ==========================================

-- 8. Find the most frequently recorded attack types

SELECT ATTACK_TYPE,
       COUNT(*) AS INCIDENT_COUNT
FROM CYBER1
GROUP BY ATTACK_TYPE
ORDER BY INCIDENT_COUNT DESC;


-- 9. Calculate average severity by attack type

SELECT ATTACK_TYPE,
       ROUND(AVG(ATTACK_SEVERITY), 4) AS AVG_SEVERITY
FROM CYBER1
GROUP BY ATTACK_TYPE
ORDER BY AVG_SEVERITY DESC;


-- ==========================================
-- SECTION 5: INDUSTRY INVESTIGATION
-- ==========================================

-- 10. Count incidents by industry

SELECT INDUSTRY,
       COUNT(*) AS INCIDENT_COUNT
FROM CYBER1
GROUP BY INDUSTRY
ORDER BY INCIDENT_COUNT DESC;


-- 11. Calculate average severity by industry

SELECT INDUSTRY,
       ROUND(AVG(ATTACK_SEVERITY), 4) AS AVG_SEVERITY
FROM CYBER1
GROUP BY INDUSTRY
ORDER BY AVG_SEVERITY DESC;


-- ==========================================
-- SECTION 6: MITIGATION ANALYSIS
-- ==========================================

-- 12. Analyze mitigation method frequency

SELECT MITIGATION_METHOD,
       COUNT(*) AS METHOD_COUNT
FROM CYBER1
GROUP BY MITIGATION_METHOD
ORDER BY METHOD_COUNT DESC;


-- ==========================================
-- SECTION 7: SECURITY TOOL ANALYSIS
-- ==========================================

-- 13. Analyze recorded security tool values

SELECT SECURITY_TOOLS_USED,
       COUNT(*) AS TOOL_COUNT,
       ROUND(AVG(RESPONSE_TIME_MIN), 2) AS AVG_RESPONSE_TIME
FROM CYBER1
GROUP BY SECURITY_TOOLS_USED
ORDER BY TOOL_COUNT DESC;


-- ==========================================
-- SECTION 8: RESPONSE TIME ANALYSIS
-- ==========================================

-- 14. Find minimum, maximum and average response time

SELECT MIN(RESPONSE_TIME_MIN) AS MIN_RESPONSE_TIME,
       MAX(RESPONSE_TIME_MIN) AS MAX_RESPONSE_TIME,
       ROUND(AVG(RESPONSE_TIME_MIN), 4) AS AVG_RESPONSE_TIME
FROM CYBER1;


-- 15. Analyze response categories

SELECT RESPONSE_CATEGORY,
       COUNT(*) AS INCIDENT_COUNT
FROM CYBER1
GROUP BY RESPONSE_CATEGORY
ORDER BY INCIDENT_COUNT DESC;

-- ==========================================
-- SECTION 9: CASE EXPRESSIONS
-- ==========================================

-- 16. Classify incidents based on attack severity

SELECT ATTACK_TYPE,
       ATTACK_SEVERITY,
       CASE
           WHEN ATTACK_SEVERITY >= 8 THEN 'High'
           WHEN ATTACK_SEVERITY >= 5 THEN 'Medium'
           ELSE 'Low'
       END AS SEVERITY_GROUP
FROM CYBER1;


-- 17. Count incidents by derived severity group

SELECT
       CASE
           WHEN ATTACK_SEVERITY >= 8 THEN 'High'
           WHEN ATTACK_SEVERITY >= 5 THEN 'Medium'
           ELSE 'Low'
       END AS SEVERITY_GROUP,
       COUNT(*) AS INCIDENT_COUNT
FROM CYBER1
GROUP BY
       CASE
           WHEN ATTACK_SEVERITY >= 8 THEN 'High'
           WHEN ATTACK_SEVERITY >= 5 THEN 'Medium'
           ELSE 'Low'
       END
ORDER BY INCIDENT_COUNT DESC;

-- ==========================================
-- SECTION 10: CONDITIONAL AGGREGATION
-- ==========================================

-- 18. Count high and low severity incidents

SELECT
    SUM(CASE WHEN ATTACK_SEVERITY >= 8
        THEN 1 ELSE 0 END) AS HIGH_SEVERITY,
    SUM(CASE WHEN ATTACK_SEVERITY < 8
        THEN 1 ELSE 0 END) AS BELOW_HIGH_SEVERITY
FROM CYBER1;


-- 19. Analyze severity levels by industry

SELECT INDUSTRY,
       COUNT(*) AS TOTAL_INCIDENTS,
       SUM(CASE WHEN ATTACK_SEVERITY >= 8
           THEN 1 ELSE 0 END) AS HIGH_SEVERITY_COUNT
FROM CYBER1
GROUP BY INDUSTRY
ORDER BY HIGH_SEVERITY_COUNT DESC;

-- ==========================================
-- SECTION 11: SUBQUERIES
-- ==========================================

-- 20. Find incidents with severity above overall average

SELECT *
FROM CYBER1
WHERE ATTACK_SEVERITY >
      (SELECT AVG(ATTACK_SEVERITY)
       FROM CYBER1);


-- 21. Find attack types having high-severity incidents

SELECT DISTINCT ATTACK_TYPE
FROM CYBER1
WHERE ATTACK_TYPE IN
      (SELECT ATTACK_TYPE
       FROM CYBER1
       WHERE ATTACK_SEVERITY >= 8);


-- 22. Find attack types with average severity
-- below the overall average

SELECT ATTACK_TYPE,
       AVG(ATTACK_SEVERITY) AS AVG_SEVERITY
FROM CYBER1
GROUP BY ATTACK_TYPE
HAVING AVG(ATTACK_SEVERITY) <
       (SELECT AVG(ATTACK_SEVERITY)
        FROM CYBER1);


-- 23. Correlated subquery:
-- Find incidents above their attack type's average severity

SELECT C1.ATTACK_TYPE,
       C1.ATTACK_SEVERITY
FROM CYBER1 C1
WHERE C1.ATTACK_SEVERITY >
      (SELECT AVG(C2.ATTACK_SEVERITY)
       FROM CYBER1 C2
       WHERE C2.ATTACK_TYPE = C1.ATTACK_TYPE);


-- 24. EXISTS: Find industries with high-severity incidents

SELECT DISTINCT C1.INDUSTRY
FROM CYBER1 C1
WHERE EXISTS
      (SELECT 1
       FROM CYBER1 C2
       WHERE C2.INDUSTRY = C1.INDUSTRY
       AND C2.ATTACK_SEVERITY >= 8);


-- 25. NOT EXISTS: Find industries without high-severity incidents

SELECT DISTINCT C1.INDUSTRY
FROM CYBER1 C1
WHERE NOT EXISTS
      (SELECT 1
       FROM CYBER1 C2
       WHERE C2.INDUSTRY = C1.INDUSTRY
       AND C2.ATTACK_SEVERITY >= 8);


-- 26. Subquery inside FROM

SELECT ATTACK_TYPE,
       AVG_SEVERITY
FROM
      (SELECT ATTACK_TYPE,
              AVG(ATTACK_SEVERITY) AS AVG_SEVERITY
       FROM CYBER1
       GROUP BY ATTACK_TYPE)
WHERE AVG_SEVERITY >
      (SELECT AVG(ATTACK_SEVERITY)
       FROM CYBER1);


-- 27. Subquery inside SELECT

SELECT ATTACK_TYPE,
       COUNT(*) AS INCIDENT_COUNT,
       (SELECT ROUND(AVG(ATTACK_SEVERITY), 2)
        FROM CYBER1) AS OVERALL_AVG_SEVERITY
FROM CYBER1
GROUP BY ATTACK_TYPE;

-- ==========================================
-- SECTION 12: COMMON TABLE EXPRESSIONS
-- ==========================================

-- 28. Compare attack type severity with overall average

WITH ATTACK_ANALYSIS AS
(
    SELECT ATTACK_TYPE,
           COUNT(*) AS INCIDENT_COUNT,
           AVG(ATTACK_SEVERITY) AS AVG_SEVERITY
    FROM CYBER1
    GROUP BY ATTACK_TYPE
)
SELECT ATTACK_TYPE,
       INCIDENT_COUNT,
       ROUND(AVG_SEVERITY, 4) AS AVG_SEVERITY
FROM ATTACK_ANALYSIS
WHERE AVG_SEVERITY >
      (SELECT AVG(ATTACK_SEVERITY)
       FROM CYBER1)
ORDER BY AVG_SEVERITY DESC;
