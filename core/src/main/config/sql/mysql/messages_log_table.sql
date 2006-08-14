USE quickfix;

DROP TABLE IF EXISTS messages_log;

CREATE TABLE messages_log (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  time DATETIME NOT NULL,
  beginstring CHAR(8) NOT NULL,
  sendercompid VARCHAR(64) NOT NULL,
  targetcompid VARCHAR(64) NOT NULL,
  session_qualifier VARCHAR(64) NOT NULL,
  text TEXT NOT NULL,
  PRIMARY KEY (id)
);