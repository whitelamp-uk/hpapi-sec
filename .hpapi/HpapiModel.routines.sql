
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
 ,IN        `ts` INT(11) unsigned
)  
BEGIN  
  SET @qry = CONCAT(
          "UPDATE `hpapi_user` SET `locked_until`='"
         ,FROM_UNIXTIME(ts)
         ,"'' WHERE `id` IN ("
         ,uids
         ,")"
      )
  ;
  PREPARE stmt FROM @qry
  ;
  EXECUTE stmt
  ;
END$$


DROP PROCEDURE IF EXISTS `hpapiSecAuth`$$
CREATE PROCEDURE `hpapiSecAuth`(
  IN        `earliest` INT(11) UNSIGNED
 ,IN        `latest` INT(11) UNSIGNED
 ,IN        `qty` INT(11) UNSIGNED
 ,IN        `within` INT(11) UNSIGNED
)  
BEGIN  
  SELECT
    `log`.`datetime`
   ,`log`.`microtime`
   ,`log`.`user_id` AS `userId`
   ,`log`.`key`
   ,(COUNT(*)+1) AS `matches`
  FROM `hpapi_log` AS `log`
  INNER JOIN `hpapi_log` AS `earlier`
          ON `earlier`.`user_id`=`log`.`user_id`
         AND `earlier`.`status`!='068'
         AND UNIX_TIMESTAMP(`earlier`.`datetime`)>(UNIX_TIMESTAMP(`log`.`datetime`)-within)
         AND `earlier`.`datetime`<=`log`.`datetime`
         AND `earlier`.`microtime`<`log`.`microtime`
  LEFT JOIN `hpapi_log` AS `later`
         ON `later`.`user_id`=`log`.`user_id`
        AND `later`.`status`!='068'
        AND `later`.`datetime`<FROM_UNIXTIME(latest)
        AND (
               `later`.`datetime`>`log`.`datetime`
          OR (
               `later`.`datetime`=`log`.`datetime`
           AND `later`.`microtime`>`log`.`microtime`
          )
        )
  WHERE `log`.`status`!='068'
    AND `log`.`datetime`>=FROM_UNIXTIME(earliest)
    AND `log`.`datetime`<FROM_UNIXTIME(latest)
    AND `later`.`datetime` IS NULL
  GROUP BY `log`.`datetime`,`log`.`microtime`,`log`.`key`
    HAVING COUNT(*)>=qty
  ;
END$$


DROP PROCEDURE IF EXISTS `hpapiSecIpLim`$$
CREATE PROCEDURE `hpapiSecIpLim`(
  IN        `earliest` INT(11) UNSIGNED
 ,IN        `latest` INT(11) UNSIGNED
 ,IN        `qty` INT(11) UNSIGNED
 ,IN        `within` INT(11) UNSIGNED
)
BEGIN
  SELECT
    `log`.`datetime`
   ,`log`.`microtime`
   ,`log`.`user_id` AS `userId`
   ,`log`.`key`
   ,(COUNT(DISTINCT `earlier`.`remote_addr`)+1) AS `matches`
  FROM `hpapi_log` AS `log`
  INNER JOIN `hpapi_log` AS `earlier`
          ON `earlier`.`remote_addr`=`log`.`remote_addr`
         AND `earlier`.`user_id`!=`log`.`user_id`
         AND UNIX_TIMESTAMP(`earlier`.`datetime`)>(UNIX_TIMESTAMP(`log`.`datetime`)-within)
         AND `earlier`.`datetime`<=`log`.`datetime`
         AND `earlier`.`microtime`<`log`.`microtime`
  LEFT JOIN `hpapi_log` AS `later`
         ON `later`.`remote_addr`=`log`.`remote_addr`
        AND `later`.`datetime`<FROM_UNIXTIME(latest)
        AND (
               `later`.`datetime`>`log`.`datetime`
          OR (
               `later`.`datetime`=`log`.`datetime`
           AND `later`.`microtime`>`log`.`microtime`
          )
        )
  WHERE `log`.`datetime`>=FROM_UNIXTIME(earliest)
    AND `log`.`datetime`<FROM_UNIXTIME(latest)
    AND `later`.`datetime` IS NULL
  GROUP BY `log`.`datetime`,`log`.`microtime`,`log`.`key`
    HAVING COUNT(DISTINCT `earlier`.`remote_addr`)>=qty
  ;
END$$


DROP PROCEDURE IF EXISTS `hpapiSecKey`$$
CREATE PROCEDURE `hpapiSecKey`(
  IN        `earliest` INT(11) UNSIGNED
 ,IN        `latest` INT(11) UNSIGNED
 ,IN        `qty` INT(11) UNSIGNED
 ,IN        `within` INT(11) UNSIGNED
)  
BEGIN  
  SELECT
    `log`.`datetime`
   ,`log`.`microtime`
   ,`log`.`user_id` AS `userId`
   ,`log`.`key`
   ,(COUNT(DISTINCT `earlier`.`user_id`)+1) AS `matches`
  FROM `hpapi_log` AS `log`
  INNER JOIN `hpapi_log` AS `earlier`
          ON `earlier`.`key`=`log`.`key`
         AND `earlier`.`user_id`!=`log`.`user_id`
         AND UNIX_TIMESTAMP(`earlier`.`datetime`)>(UNIX_TIMESTAMP(`log`.`datetime`)-within)
         AND `earlier`.`datetime`<=`log`.`datetime`
         AND `earlier`.`microtime`<`log`.`microtime`
  LEFT JOIN `hpapi_log` AS `later`
         ON `later`.`key`=`log`.`key`
        AND `later`.`datetime`<FROM_UNIXTIME(latest)
        AND (
               `later`.`datetime`>`log`.`datetime`
          OR (
               `later`.`datetime`=`log`.`datetime`
           AND `later`.`microtime`>`log`.`microtime`
          )
        )
  WHERE `log`.`key`!=''
    AND `log`.`datetime`>=FROM_UNIXTIME(earliest)
    AND `log`.`datetime`<FROM_UNIXTIME(latest)
    AND `later`.`datetime` IS NULL
  GROUP BY `log`.`datetime`,`log`.`microtime`,`log`.`key`
    HAVING COUNT(DISTINCT `earlier`.`user_id`)>=1
  ;
END$$


DROP PROCEDURE IF EXISTS `hpapiSecPwd`$$
-- Requires logging of bad passwords (hashed?) before it can be completed and implemented
CREATE PROCEDURE `hpapiSecPwd`(
  IN        `earliest` INT(11) UNSIGNED
 ,IN        `latest` INT(11) UNSIGNED
 ,IN        `qty` INT(11) UNSIGNED
 ,IN        `within` INT(11) UNSIGNED
)  
BEGIN  
  SELECT
    `log`.`datetime`
   ,`log`.`microtime`
   ,`log`.`user_id` AS `userId`
   ,`log`.`key`
   ,(COUNT(DISTINCT `earlier`.`user_id`)+1) AS `matches`
  FROM `hpapi_log` AS `log`
  INNER JOIN `hpapi_log` AS `earlier`
          ON `earlier`.`bad_password`=`log`.`bad_password`
         AND `earlier`.`user_id`!=`log`.`user_id`
         AND UNIX_TIMESTAMP(`earlier`.`datetime`)>(UNIX_TIMESTAMP(`log`.`datetime`)-within)
         AND `earlier`.`datetime`<=`log`.`datetime`
         AND `earlier`.`microtime`<`log`.`microtime`
  LEFT JOIN `hpapi_log` AS `later`
         ON `later`.`bad_password`=`log`.`key`
        AND `later`.`datetime`<FROM_UNIXTIME(latest)
        AND (
               `later`.`datetime`>`log`.`datetime`
          OR (
               `later`.`datetime`=`log`.`datetime`
           AND `later`.`microtime`>`log`.`microtime`
          )
        )
  WHERE `log`.`datetime`>=FROM_UNIXTIME(earliest)
    AND `log`.`datetime`<FROM_UNIXTIME(latest)
    AND `later`.`datetime` IS NULL
  GROUP BY `log`.`datetime`,`log`.`microtime`,`log`.`key`
    HAVING COUNT(DISTINCT `earlier`.`user_id`)>=1
  ;
END$$


DROP PROCEDURE IF EXISTS `hpapiSecReq`$$
CREATE PROCEDURE `hpapiSecReq`(
  IN        `earliest` INT(11) UNSIGNED
 ,IN        `latest` INT(11) UNSIGNED
 ,IN        `qty` INT(11) UNSIGNED
 ,IN        `within` INT(11) UNSIGNED
)
BEGIN
  SELECT
    `log`.`datetime`
   ,`log`.`microtime`
   ,`log`.`user_id` AS `userId`
   ,`log`.`key`
   ,(COUNT(*)+1) AS `matches`
  FROM `hpapi_log` AS `log`
  INNER JOIN `hpapi_log` AS `earlier`
          ON `earlier`.`user_id`=`log`.`user_id`
         AND UNIX_TIMESTAMP(`earlier`.`datetime`)>(UNIX_TIMESTAMP(`log`.`datetime`)-within)
         AND `earlier`.`datetime`<=`log`.`datetime`
         AND `earlier`.`microtime`<`log`.`microtime`
  LEFT JOIN `hpapi_log` AS `later`
         ON `later`.`user_id`=`log`.`user_id`
        AND `later`.`datetime`<FROM_UNIXTIME(latest)
        AND (
               `later`.`datetime`>`log`.`datetime`
          OR (
               `later`.`datetime`=`log`.`datetime`
           AND `later`.`microtime`>`log`.`microtime`
          )
        )
  WHERE `log`.`datetime`>=FROM_UNIXTIME(earliest)
    AND `log`.`datetime`<FROM_UNIXTIME(latest)
    AND `later`.`datetime` IS NULL
  GROUP BY `log`.`datetime`,`log`.`microtime`,`log`.`key`
    HAVING COUNT(*)>=qty
  ;
END$$


DELIMITER ;


