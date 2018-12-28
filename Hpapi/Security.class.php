<?php

/* Copyright 2018 Whitelamp http://www.whitelamp.com/ */

namespace Hpapi;

class Security {

    protected $jobs;
    protected $hpapi;
    protected $userId;
    protected $blacklist;
    protected $tmp;
    protected $fp;
    protected $lines = 0;
    protected $itemCount = 0;
    protected $items = array ();

    public function __construct (\Hpapi\Hpapi $hpapi) {
        $config                 = json_decode (file_get_contents(HPAPI_SEC_CONFIG));
        $this->jobs             = $config->jobs;
        $this->hpapi            = $hpapi;
        $this->userId           = $this->hpapi->userId;
        $this->dt               = new \DateTime ('@'.$this->hpapi->timestamp);
        $this->uids             = array ();
        $pid                    = getmypid ();
        $this->tmp              = HPAPI_SEC_DIGEST_TMP.$pid.'.tmp';
    }

    public function __destruct ( ) {
    }

/* API */

    public function job ($job) {
        if (!property_exists($this->jobs,$job)) {
            throw new \Exception (HPAPI_SEC_EXCEPT_JOB);
            return false;
        }
        $scope                  = $this->jobs->{$job}->scanSeconds;
        $this->blacklist        = new \stdClass ();
        $this->fp               = fopen ($this->tmp,'a');
        $this->digestStart ($job);
        foreach ($this->jobs->{$job}->rules as $rule) {
            $rows               = $this->{'method_'.$rule->method} ($scope,$rule->hits,$rule->withinSeconds);
            foreach ($rows as $row) {
                $this->digest ($this->dt->format(\DateTime::ATOM),$rule->method,$this->digestLine($row),$rule->withinSeconds);
                $this->blacklist ($rule->method,$row,$this->timestamp+$rule->userLockSeconds);
            }
        }
        $this->digestEnd ();
        $this->blacklistEnd ();
        fclose ($this->fp);
        rename ($this->tmp,HPAPI_SEC_DIGEST);
        $this->hpapi->exportArray (HPAPI_SEC_BLACKLIST,$this->items);
        return true;
    }

/* Rule methods */

    protected function method_auth ($scope,$count,$within) {
        return $this->find ('hpapiSecAuth',$scope,$count,$within);
/*
    Find failed authentications within a time scope (from now) that
    match too many failed authentications within a number of seconds
    for the same user
*/
    }

    protected function method_iplim ($scope,$count,$within) {
        return $this->find ('hpapiSecIpLim',$scope,$count,$within);
/*
    Find requests within a time scope (from now) that
    match too many distinct remote addresses within a number of seconds
    for the same user
*/
    }

    protected function method_key ($scope,$count,$within) {
        return $this->find ('hpapiSecKey',$scope,$count,$within);
/*
    Find failed authentications within a time scope (from now) that
    match too many users within a number of seconds
    for the same key
*/
    }

    protected function method_pwd ($scope,$count,$within) {
return array ();
        return $this->find ('hpapiSecPwd',$scope,$count,$within);
/*
    Find failed authentications within a time scope (from now) that
    match too many users within a number of seconds
    for the same password
    Requires logging of bad passwords (hashed?) before it can be implemented
*/
    }

    protected function method_req ($scope,$count,$within) {
        return $this->find ('hpapiSecReq',$scope,$count,$within);
/*
    Find requests within a time scope (from now) that
    match too many requests within a number of seconds
    for the same user
*/
    }

/* Utilities */

    protected function blacklist ($mtd,$row,$lock) {
        if ($this->itemCount>=HPAPI_SEC_BLACKLIST_ITEMS) {
            return;
        }
        if ($mtd=='iplim') {
            $attribute  = 'remoteAddr';
        }
        elseif ($mtd=='key') {
            $attribute  = 'key';
        }
        elseif ($mtd=='pwd') {
            $attribute  = 'badPassword';
        }
        else {
            $attribute  = 'email';
        }
        array_push ($this->items,array($attribute,$row[$attribute],$lock));
    }

    protected function blacklistEnd ( ) {
        if ($this->itemCount>=HPAPI_SEC_BLACKLIST_ITEMS) {
            return;
        }
        $b = false;
        try {
            if (is_readable(HPAPI_SEC_BLACKLIST)) {
                $b = include HPAPI_SEC_BLACKLIST;
            }
        }
        catch (\Exception $e) {
            return;
        }
        if (!is_array($b) || !count($b)) {
            return;
        }
        foreach ($b as $item) {
            if ($this->itemCount>=HPAPI_SEC_BLACKLIST_ITEMS) {
                break;
            }
            array_push ($this->items,$item);
            $this->itemCount++;
        }
    }

    protected function digest ($ts,$mtd,$row,$secs) {
        if ($this->lines>=HPAPI_SEC_DIGEST_LINES) {
            return;
        }
        foreach ($row as $k=>$v) {
            $row[$k] = trim ($v);
            if ($row[$k]=='') {
                $row[$k] = '-';
            }
        }
        $row = implode (' ',$row);
        fwrite ($this->fp,$ts.' '.$mtd.': '.$row.' / '.$secs."\n");
        $this->lines++;
    }

    protected function digestEnd ( ) {
        if ($this->lines>=HPAPI_SEC_DIGEST_LINES) {
            return;
        }
        $lines      = array ();
        if (file_exists(HPAPI_SEC_DIGEST)) {
            $lines  = file (HPAPI_SEC_DIGEST);
        }
        foreach ($lines as $line) {
            if ($this->lines>=HPAPI_SEC_DIGEST_LINES) {
                break;
            }
            fwrite ($this->fp,$line);
            $this->lines++;
        }
    }

    protected function digestStart ($job) {
            fwrite ($this->fp,'# JOB: '.$job."\n");
    }

    protected function find ($spr,$scope,$count,$within) {
        $rows = $this->hpapi->dbCall (
            $spr
           ,$this->hpapi->timestamp - intval ($scope)
           ,$this->hpapi->timestamp
           ,$count
           ,$within
        );
        return $rows;
    }

}

