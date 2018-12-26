
-- Copyright 2018 Whitelamp http://www.whitelamp.com/

SET NAMES utf8;
SET time_zone = '+00:00';


DELIMITER $$


DROP PROCEDURE IF EXISTS `hpapiInsertSystemUser`$$
CREATE PROCEDURE `hpapiInsertSystemUser`(
  IN        `em` VARCHAR(254) CHARSET ascii
)
BEGIN
  INSERT INTO `hpapi_user` (`active`, `uuid`, `key`, `key_expired`, `key_release`, `key_release_until`, `remote_addr_pattern`, `name`, `notes`, `email`, `email_verified`, `email_fallback`, `email_fallback_verified`, `password_hash`) VALUES
    (1,	'000891b3-0912-11e9-b658-6d7f358a16ce',	'9894c0d9-0913-11e9-b658-6d7f358a16ce',	0,	0,	'0000-00-00 00:00:00',	'^::1$',	'System user',	'Used for system processes calling API from localhost',	em,	1,	'',	0,	'$2y$10$hLSdApW6.30YLK3ze49uSu7OV0gmS3ZT65pufxDPGiMxsmW3bykeq')
  ;
  INSERT INTO `hpapi_membership` (`user_id`, `usergroup`) VALUES
    (LAST_INSERT_ID(),	'system')
  ;
  SELECT 'Inserted system user into hpapi_user and hpapi_membership' AS `Completed`
  ;
END$$


DROP PROCEDURE IF EXISTS `hpapiSecLock`$$
CREATE PROCEDURE `hpapiSecLock`(
  IN        `uids` VARCHAR(255) CHARSET ascii
)  
BEGIN  
  SET @qry = CONCAT(
          'UPDATE `hpapi_user` SET `locked`=1 WHERE `id` IN ('
         ,uids
         ,')'
      )
  ;
  PREPARE stmt FROM @qry
  ;
  EXECUTE stmt
  ;
END$$


DROP PROCEDURE IF EXISTS `hpapiSecAuth`$$
CREATE PROCEDURE `hpapiSecAuth`(
  IN        `then` INT(11) UNSIGNED
 ,IN        `now` INT(11) UNSIGNED
 ,IN        `qty` INT(11) UNSIGNED
 ,IN        `within` INT(11) UNSIGNED
)  
BEGIN  
  SELECT
    `log`.*
   ,COUNT(*) AS `matches`
    FROM `hpapi_log` AS `log`
    LEFT JOIN `hpapi_log` AS `match`
           ON `match`.`email`=`log`.`email`
    WHERE `hpapi_log`.`email`='blah'
    GROUP BY `log`.`datetime`,`log`.`microtime`,`log`.`key`
  ;
END$$


DROP PROCEDURE IF EXISTS `hpapiSecIpDeny`$$
CREATE PROCEDURE `hpapiSecIpDeny`(
  IN        `then` INT(11) UNSIGNED
 ,IN        `now` INT(11) UNSIGNED
 ,IN        `qty` INT(11) UNSIGNED
 ,IN        `within` INT(11) UNSIGNED
)  
BEGIN  
  SELECT
    `log`.*
   ,COUNT(*) AS `matches`
    FROM `hpapi_log` AS `log`
    LEFT JOIN `hpapi_log` AS `match`
           ON `match`.`email`=`log`.`email`
    WHERE `hpapi_log`.`email`='blah'
    GROUP BY `log`.`datetime`,`log`.`microtime`,`log`.`key`
  ;
END$$


DROP PROCEDURE IF EXISTS `hpapiSecIpLim`$$
CREATE PROCEDURE `hpapiSecIpLim`(
  IN        `then` INT(11) UNSIGNED
 ,IN        `now` INT(11) UNSIGNED
 ,IN        `qty` INT(11) UNSIGNED
 ,IN        `within` INT(11) UNSIGNED
)  
BEGIN  
  SELECT
    `log`.*
   ,COUNT(*) AS `matches`
    FROM `hpapi_log` AS `log`
    LEFT JOIN `hpapi_log` AS `match`
           ON `match`.`email`=`log`.`email`
    WHERE `hpapi_log`.`email`='blah'
    GROUP BY `log`.`datetime`,`log`.`microtime`,`log`.`key`
  ;
END$$


DROP PROCEDURE IF EXISTS `hpapiSecKey`$$
CREATE PROCEDURE `hpapiSecKey`(
  IN        `then` INT(11) UNSIGNED
 ,IN        `now` INT(11) UNSIGNED
 ,IN        `qty` INT(11) UNSIGNED
 ,IN        `within` INT(11) UNSIGNED
)  
BEGIN  
  SELECT
    `log`.*
   ,COUNT(*) AS `matches`
    FROM `hpapi_log` AS `log`
    LEFT JOIN `hpapi_log` AS `match`
           ON `match`.`email`=`log`.`email`
    WHERE `hpapi_log`.`email`='blah'
    GROUP BY `log`.`datetime`,`log`.`microtime`,`log`.`key`
  ;
END$$


DROP PROCEDURE IF EXISTS `hpapiSecPwd`$$
CREATE PROCEDURE `hpapiSecPwd`(
  IN        `then` INT(11) UNSIGNED
 ,IN        `now` INT(11) UNSIGNED
 ,IN        `qty` INT(11) UNSIGNED
 ,IN        `within` INT(11) UNSIGNED
)  
BEGIN  
  SELECT
    `log`.*
   ,COUNT(*) AS `matches`
    FROM `hpapi_log` AS `log`
    LEFT JOIN `hpapi_log` AS `match`
           ON `match`.`email`=`log`.`email`
    WHERE `hpapi_log`.`email`='blah'
    GROUP BY `log`.`datetime`,`log`.`microtime`,`log`.`key`
  ;
END$$


DROP PROCEDURE IF EXISTS `hpapiSecReq`$$
CREATE PROCEDURE `hpapiSecReq`(
  IN        `then` INT(11) UNSIGNED
 ,IN        `now` INT(11) UNSIGNED
 ,IN        `qty` INT(11) UNSIGNED
 ,IN        `within` INT(11) UNSIGNED
)  
BEGIN  
  SELECT
    `log`.*
   ,COUNT(*) AS `matches`
    FROM `hpapi_log` AS `log`
    LEFT JOIN `hpapi_log` AS `match`
           ON `match`.`email`=`log`.`email`
    WHERE `hpapi_log`.`email`='blah'
    GROUP BY `log`.`datetime`,`log`.`microtime`,`log`.`key`
  ;
END$$


DELIMITER ;


