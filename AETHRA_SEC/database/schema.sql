-- =====================================================================
-- AETHRA-SEC MySQL schema
-- All statements are idempotent (CREATE TABLE IF NOT EXISTS) so the
-- schema can be applied repeatedly without error.
-- Engine: InnoDB (foreign keys + transactions). Charset: utf8mb4.
-- =====================================================================

-- --------------------------------------------------------------------
-- Users & authentication
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(32)  NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    fullname        VARCHAR(120) NOT NULL DEFAULT '',
    email           VARCHAR(160) NOT NULL DEFAULT '',
    role            ENUM('admin','user') NOT NULL DEFAULT 'user',
    status          ENUM('active','inactive','locked') NOT NULL DEFAULT 'active',
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until    DATETIME NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login      DATETIME NULL,
    INDEX idx_users_role (role),
    INDEX idx_users_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_history (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT NULL,
    username      VARCHAR(32) NOT NULL DEFAULT '',
    login_time    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    logout_time   DATETIME NULL,
    ip_address    VARCHAR(45) NOT NULL DEFAULT '',
    computer_name VARCHAR(120) NOT NULL DEFAULT '',
    status        VARCHAR(32) NOT NULL DEFAULT 'success',
    CONSTRAINT fk_login_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_login_user (user_id),
    INDEX idx_login_time (login_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- Vulnerability assessment (Nmap)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerability_scans (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    scan_name        VARCHAR(160) NOT NULL DEFAULT '',
    target_ip        VARCHAR(160) NOT NULL,
    scan_type        VARCHAR(48)  NOT NULL DEFAULT 'quick',
    started_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at      DATETIME NULL,
    duration         DECIMAL(10,2) NOT NULL DEFAULT 0,
    total_hosts      INT NOT NULL DEFAULT 0,
    total_open_ports INT NOT NULL DEFAULT 0,
    highest_risk     VARCHAR(20) NOT NULL DEFAULT 'Informational',
    status           VARCHAR(24) NOT NULL DEFAULT 'running',
    created_by       INT NULL,
    CONSTRAINT fk_scan_user FOREIGN KEY (created_by)
        REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_scan_status (status),
    INDEX idx_scan_started (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS scan_results (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    scan_id       INT NOT NULL,
    host          VARCHAR(64) NOT NULL,
    hostname      VARCHAR(160) NOT NULL DEFAULT '',
    mac_address   VARCHAR(32) NOT NULL DEFAULT '',
    vendor        VARCHAR(120) NOT NULL DEFAULT '',
    os_guess      VARCHAR(160) NOT NULL DEFAULT '',
    port          INT NOT NULL DEFAULT 0,
    protocol      VARCHAR(12) NOT NULL DEFAULT 'tcp',
    service       VARCHAR(64) NOT NULL DEFAULT '',
    product       VARCHAR(120) NOT NULL DEFAULT '',
    version       VARCHAR(120) NOT NULL DEFAULT '',
    state         VARCHAR(24) NOT NULL DEFAULT 'open',
    risk_level    VARCHAR(20) NOT NULL DEFAULT 'Informational',
    cve_reference VARCHAR(255) NOT NULL DEFAULT '',
    description   TEXT NULL,
    CONSTRAINT fk_result_scan FOREIGN KEY (scan_id)
        REFERENCES vulnerability_scans(id) ON DELETE CASCADE,
    INDEX idx_result_scan (scan_id),
    INDEX idx_result_host (host),
    INDEX idx_result_risk (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- Live monitoring (PyShark)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS live_packets (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp        DATETIME(3) NOT NULL,
    source_ip        VARCHAR(64) NOT NULL DEFAULT '',
    destination_ip   VARCHAR(64) NOT NULL DEFAULT '',
    source_port      INT NOT NULL DEFAULT 0,
    destination_port INT NOT NULL DEFAULT 0,
    protocol         VARCHAR(16) NOT NULL DEFAULT '',
    transport        VARCHAR(16) NOT NULL DEFAULT '',
    application      VARCHAR(48) NOT NULL DEFAULT '',
    packet_length    INT NOT NULL DEFAULT 0,
    ttl              INT NOT NULL DEFAULT 0,
    tcp_flags        VARCHAR(32) NOT NULL DEFAULT '',
    mac_source       VARCHAR(32) NOT NULL DEFAULT '',
    mac_destination  VARCHAR(32) NOT NULL DEFAULT '',
    direction        VARCHAR(16) NOT NULL DEFAULT '',
    INDEX idx_pkt_time (timestamp),
    INDEX idx_pkt_src (source_ip),
    INDEX idx_pkt_proto (protocol)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS traffic_statistics (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp          DATETIME NOT NULL,
    packets_per_second DECIMAL(12,2) NOT NULL DEFAULT 0,
    bytes_per_second   DECIMAL(14,2) NOT NULL DEFAULT 0,
    active_connections INT NOT NULL DEFAULT 0,
    tcp_count          BIGINT NOT NULL DEFAULT 0,
    udp_count          BIGINT NOT NULL DEFAULT 0,
    icmp_count         BIGINT NOT NULL DEFAULT 0,
    http_count         BIGINT NOT NULL DEFAULT 0,
    https_count        BIGINT NOT NULL DEFAULT 0,
    dns_count          BIGINT NOT NULL DEFAULT 0,
    INDEX idx_stat_time (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS devices (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    ip_address       VARCHAR(64) NOT NULL UNIQUE,
    hostname         VARCHAR(160) NOT NULL DEFAULT '',
    mac_address      VARCHAR(32) NOT NULL DEFAULT '',
    vendor           VARCHAR(120) NOT NULL DEFAULT '',
    operating_system VARCHAR(160) NOT NULL DEFAULT '',
    first_seen       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status           VARCHAR(16) NOT NULL DEFAULT 'Online',
    packets_sent     BIGINT NOT NULL DEFAULT 0,
    packets_received BIGINT NOT NULL DEFAULT 0,
    open_ports       VARCHAR(255) NOT NULL DEFAULT '',
    risk_level       VARCHAR(20) NOT NULL DEFAULT 'Informational',
    INDEX idx_device_status (status),
    INDEX idx_device_risk (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- Intrusion detection (Snort)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS intrusion_alerts (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    timestamp        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    snort_sid        VARCHAR(32) NOT NULL DEFAULT '',
    classification   VARCHAR(160) NOT NULL DEFAULT '',
    category         VARCHAR(48) NOT NULL DEFAULT 'Unknown Threat',
    priority         INT NOT NULL DEFAULT 3,
    source_ip        VARCHAR(64) NOT NULL DEFAULT '',
    destination_ip   VARCHAR(64) NOT NULL DEFAULT '',
    source_port      INT NOT NULL DEFAULT 0,
    destination_port INT NOT NULL DEFAULT 0,
    protocol         VARCHAR(16) NOT NULL DEFAULT '',
    interface        VARCHAR(64) NOT NULL DEFAULT '',
    description      TEXT NULL,
    severity         VARCHAR(20) NOT NULL DEFAULT 'Medium',
    occurrences      INT NOT NULL DEFAULT 1,
    status           VARCHAR(24) NOT NULL DEFAULT 'Open',
    dedup_key        VARCHAR(191) NOT NULL DEFAULT '',
    fp_reason        VARCHAR(255) NOT NULL DEFAULT '',
    fp_user          VARCHAR(32) NOT NULL DEFAULT '',
    fp_date          DATETIME NULL,
    admin_notes      TEXT NULL,
    INDEX idx_alert_time (timestamp),
    INDEX idx_alert_sev (severity),
    INDEX idx_alert_status (status),
    INDEX idx_alert_cat (category),
    UNIQUE KEY uq_alert_dedup (dedup_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS alert_timeline (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    alert_id   INT NOT NULL,
    timestamp  DATETIME(3) NOT NULL,
    event      VARCHAR(255) NOT NULL DEFAULT '',
    CONSTRAINT fk_timeline_alert FOREIGN KEY (alert_id)
        REFERENCES intrusion_alerts(id) ON DELETE CASCADE,
    INDEX idx_timeline_alert (alert_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- Mitigation knowledge base
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mitigation_recommendations (
    id                   INT AUTO_INCREMENT PRIMARY KEY,
    alert_type           VARCHAR(48) NOT NULL UNIQUE,
    severity             VARCHAR(20) NOT NULL DEFAULT 'Medium',
    recommendation_title VARCHAR(200) NOT NULL DEFAULT '',
    explanation          TEXT NULL,
    educational          TEXT NULL,
    problem              TEXT NULL,
    why_it_happened      TEXT NULL,
    risk                 TEXT NULL,
    how_to_verify        TEXT NULL,
    immediate_actions    TEXT NULL,
    long_term_prevention TEXT NULL,
    recommendation       TEXT NULL,
    reference            TEXT NULL,
    difficulty           VARCHAR(24) NOT NULL DEFAULT 'Moderate',
    admin_notes          TEXT NULL,
    INDEX idx_mit_type (alert_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- Logging & auditing
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system_logs (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    module      VARCHAR(48) NOT NULL DEFAULT '',
    action      VARCHAR(96) NOT NULL DEFAULT '',
    description TEXT NULL,
    user        VARCHAR(32) NOT NULL DEFAULT 'system',
    severity    VARCHAR(16) NOT NULL DEFAULT 'INFO',
    INDEX idx_syslog_time (timestamp),
    INDEX idx_syslog_module (module),
    INDEX idx_syslog_sev (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS activity_logs (
    id        BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user      VARCHAR(32) NOT NULL DEFAULT '',
    activity  VARCHAR(96) NOT NULL DEFAULT '',
    details   TEXT NULL,
    INDEX idx_activity_time (timestamp),
    INDEX idx_activity_user (user)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- Reports & settings
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    generated_by INT NULL,
    generated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    report_type  VARCHAR(64) NOT NULL DEFAULT '',
    file_format  VARCHAR(12) NOT NULL DEFAULT 'pdf',
    filename     VARCHAR(255) NOT NULL DEFAULT '',
    CONSTRAINT fk_report_user FOREIGN KEY (generated_by)
        REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_report_time (generated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS settings (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    setting_name  VARCHAR(96) NOT NULL UNIQUE,
    setting_value TEXT NULL,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_setting_name (setting_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- Evaluation metrics (false positives / negatives, detection time)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_metrics (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    timestamp      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    metric_type    VARCHAR(32) NOT NULL DEFAULT '',
    attack_type    VARCHAR(48) NOT NULL DEFAULT '',
    detection_time DECIMAL(10,3) NOT NULL DEFAULT 0,
    detected       TINYINT(1) NOT NULL DEFAULT 0,
    notes          TEXT NULL,
    reviewed_by    VARCHAR(32) NOT NULL DEFAULT '',
    INDEX idx_metric_type (metric_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
