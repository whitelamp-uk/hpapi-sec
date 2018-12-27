<?php

/* Copyright 2018 Whitelamp http://www.whitelamp.com/ */

namespace Hpapi;

class Security {

    protected $jobs;
    protected $hpapi;
    protected $userId;
    protected $uids;
    protected $tmp;
    protected $fp;
    protected $lines = 0;

    public function __construct (\Hpapi\Hpapi $hpapi) {
        $config         = json_decode (file_get_contents(HPAPI_SEC_CONFIG));
        $this->jobs     = $config->jobs;
        $this->hpapi    = $hpapi;
        $this->userId   = $this->hpapi->userId;
        $this->dt       = new \DateTime ('@'.$this->hpapi->timestamp);
        $this->uids     = array ();
        $this->tmp      = HPAPI_SEC_LOG_TMP.getmypid().'.tmp';
    }

    public function __destruct ( ) {
    }

/* API */

    public function job ($job) {
        if (!property_exists($this->jobs,$job)) {
            throw new \Exception (HPAPI_SEC_EXCEPT_JOB);
            return false;
        }
        $this->fp       = fopen ($this->tmp,'a');
        $scope          = $this->jobs->{$job}->scanSeconds;
        foreach ($this->jobs->{$job}->rules as $rule) {
            $uids       = $this->{'method_'.$rule->method} ($scope,$rule->hits,$rule->withinSeconds);
            foreach ($uids as $row) {
                $this->uid ($row['userId'],$rule->userLockSeconds);
                $this->log ($this->dt->format(\DateTime::ATOM).' '.$rule->method.' : '.$this->logLine($row).' / '.$rule->withinSeconds);
            }
        }
        $this->lock ();
        $this->logEnd ();
        fclose ($this->fp);
        unlink (HPAPI_SEC_LOG);
        rename ($this->tmp,HPAPI_SEC_LOG);
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

    protected function logLine ($arr) {
        foreach ($arr as $k=>$v) {
            $arr[$k] = trim ($v);
            if ($arr[$k]=='') {
                $arr[$k] = '-';
            }
        }
        return implode (' ',$arr);
    }

    protected function find ($spr,$scope,$count,$within) {
        $uids   = $this->hpapi->dbCall (
            $spr
           ,$this->hpapi->timestamp - intval ($scope)
           ,$this->hpapi->timestamp
           ,$count
           ,$within
        );
        return $uids;
    }

    protected function lock ( ) {
        $uids               = '';
        $notfirst           = false;
        foreach ($this->uids as $uid=>$lock) {
            $next           = '';
            if ($notfirst) {
                if ($lock!=$firstlock) {
                    continue;
                }
                $next      .= ',';
            }
            else {
                $firstlock  = $lock;
                $notfirst   = true;
            }
            $next          .= intval ($uid);
            if ((strlen($uids)+strlen($next))>255) {
                break;
            }
            $uids          .= $next;
            unset ($this->uids[$uid]);
        }
       if (strlen($uids)) {
$this->hpapi->diagnostic ('lock: set '.($this->hpapi->timestamp+$firstlock).'for all in ('.$uids.')');
/*
            $this->hpapi->dbCall (
                'hpapiSecLock'
               ,$uids
               ,$this->hpapi->timestamp + $firstlock
        );
*/
        }
else {
$this->hpapi->diagnostic ('lock: no user IDs');
}
        if (!count($this->uids)) {
            return;
        }
        // Recurse until all done
        $this->lock ();
    }

    protected function log ($str) {
        fwrite ($this->fp,$str."\n");
        $this->lines++;
    }

    protected function logEnd ( ) {
        $lines      = array ();
        if (file_exists(HPAPI_SEC_LOG)) {
            $lines  = file (HPAPI_SEC_LOG);
        }
        foreach ($lines as $line) {
            if ($this->lines>HPAPI_SEC_LOG_LINES) {
                break;
            }
            $this->lines++;
        }
    }

    protected function uid ($uid,$lock) {
        if (array_key_exists($uid,$this->uids) && $this->uids[$uid]>$lock) {
            return;
        }
        $this->uids[$uid] = $lock;
    }

}

