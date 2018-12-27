
SET NAMES utf8;
SET time_zone = '+00:00';
SET foreign_key_checks = 0;
SET sql_mode = 'NO_AUTO_VALUE_ON_ZERO';


-- HPAPI PRIVILEGE TABLES

INSERT IGNORE INTO `hpapi_call` (`model`, `spr`, `vendor`, `package`, `class`, `method`) VALUES
('HpapiModel',	'hpapiSecAuth',	'whitelamp-uk',	'hpapi-sec',	'\\Hpapi\\Security',	'job'),
('HpapiModel',	'hpapiSecIpLim',	'whitelamp-uk',	'hpapi-sec',	'\\Hpapi\\Security',	'job'),
('HpapiModel',	'hpapiSecLock',	'whitelamp-uk',	'hpapi-sec',	'\\Hpapi\\Security',	'job'),
('HpapiModel',	'hpapiSecKey',	'whitelamp-uk',	'hpapi-sec',	'\\Hpapi\\Security',	'job'),
('HpapiModel',	'hpapiSecPwd',	'whitelamp-uk',	'hpapi-sec',	'\\Hpapi\\Security',	'job'),
('HpapiModel',	'hpapiSecReq',	'whitelamp-uk',	'hpapi-sec',	'\\Hpapi\\Security',	'job');

INSERT IGNORE INTO `hpapi_method` (`vendor`, `package`, `class`, `method`, `label`, `notes`) VALUES
('whitelamp-uk',	'hpapi-sec',	'\\Hpapi\\Security',	'job',	'Security monitoring jobs',	'');

INSERT INTO `hpapi_methodarg` (`vendor`, `package`, `class`, `method`, `argument`, `name`, `empty_allowed`, `pattern`) VALUES
('whitelamp-uk',	'hpapi-sec',	'\\Hpapi\\Security',	'job',	1,	'Job handle',	0,	'varchar-64');

INSERT IGNORE INTO `hpapi_package` (`vendor`, `package`, `requires_key`, `notes`) VALUES
('whitelamp-uk',	'hpapi-sec',	1,	'Security monitoring of hpapi_log.');

INSERT IGNORE INTO `hpapi_run` (`usergroup`, `vendor`, `package`, `class`, `method`) VALUES
('system',	'whitelamp-uk',	'hpapi-sec',	'\\Hpapi\\Security',	'job');

INSERT IGNORE INTO `hpapi_spr` (`model`, `spr`, `notes`) VALUES
('HpapiModel',	'hpapiSecAuth',	'Too many authentication failures per user.'),
('HpapiModel',	'hpapiSecIpLim',	'Too many remote addresses per user.'),
('HpapiModel',	'hpapiSecLock',	'Lock out a list of user IDs until a datetime.'),
('HpapiModel',	'hpapiSecKey',	'Too many users per key.'),
('HpapiModel',	'hpapiSecPwd',	'Too many users per password.'),
('HpapiModel',	'hpapiSecReq',	'Too many requests  per user.');

INSERT IGNORE INTO `hpapi_sprarg` (`model`, `spr`, `argument`, `name`, `empty_allowed`, `pattern`) VALUES
('HpapiModel',	'hpapiSecAuth',	1,	'Seconds start',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecAuth',	2,	'Seconds end',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecAuth',	3,	'Maximum allowed matches',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecAuth',	4,	'Seconds to match',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecIpLim',	1,	'Seconds start',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecIpLim',	2,	'Seconds end',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecIpLim',	3,	'Maximum allowed matches',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecIpLim',	4,	'Seconds to match',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecLock',	1,	'Comma-separated user IDs',	0,	'varchar-255'),
('HpapiModel',	'hpapiSecLock',	2,	'Until Unix timestamp',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecKey',	1,	'Seconds start',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecKey',	2,	'Seconds end',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecKey',	3,	'Maximum allowed matches',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecKey',	4,	'Seconds to match',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecPwd',	1,	'Seconds start',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecPwd',	2,	'Seconds end',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecPwd',	3,	'Maximum allowed matches',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecPwd',	4,	'Seconds to match',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecReq',	1,	'Seconds start',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecReq',	2,	'Seconds end',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecReq',	3,	'Maximum allowed matches',	0,	'int-11-positive'),
('HpapiModel',	'hpapiSecReq',	4,	'Seconds to match',	0,	'int-11-positive');

