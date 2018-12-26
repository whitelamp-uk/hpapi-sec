<?php

/* Copyright 2018 Whitelamp http://www.whitelamp.com/ */

namespace Hpapi;

class SecurityJob {

    protected $config;
    protected $hpapi;
    protected $userId;
    protected $now;
    protected $uids;
    protected $tmp;
    protected $fp;
    protected $lines;

    public function __construct (\Hpapi\Hpapi $hpapi) {
        $this->config   = json_decode (HPAPI_SEC_CONFIG);
        $this->hpapi    = $hpapi;
        $this->userId   = $this->hpapi->userId;
        $this->now      = time ();
        $this->dt       = new \DateTime ('@'.$this->now);
        $this->uids     = array ();
        $this->tmp      = HPAPI_SEC_LOG_TMP.getmypid().'.tmp'
        $this->lines    = HPAPI_SEC_LOG_TMP.getmypid().'.tmp'
    }

    public function __destruct ( ) {
    }

/* API */

    public function job ($job) {
        if (!property_exists($this->config->jobs,$job)) {
            throw new \Exception (HPAPI_SEC_EXCEPT_JOB);
            return false;
        }
        $this->fp       = fopen ($this->tmp,'a');
        $scope          = $this->config->jobs->{$job}->scanSeconds;
        foreach ($this->config->jobs->{$job}->rules as $rule) {
            $uids       = $this->{'method_'.$rule->method} ($scope,$rule->hits,$rule->withinSeconds);
            foreach ($uids as $row) {
                $this->uid ($row['userId'],$rule->userLockSeconds);
                $this->log ($this->dt->format(\DateTime::ATOM).' '.$rule->method.' '.$row['email'].' '.$row['matches'].'/'.$rule->withinSeconds);
            }
        }
        $this->lock ();
        $this->logEnd ();
        fclose ($this->fp);
        unlink (HPAPI_SEC_LOG);
        rename ($this->tmp,HPAPI_SEC_LOG);
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

    protected function method_ipdeny ($scope,$count,$within) {
        return $this->find ('hpapiSecIpDeny',$scope,$count,$within);
/*
    Find failed remote addresses* within a time scope (from now) that
    match too many failed remote addresses* within a number of seconds
    for the same user
    * Fail to match remote_addr_pattern for any of user, group or package
*/
    }

    protected function method_iplim ($scope,$count,$within) {
        return $this->find ('hpapiSecIpLim',$scope,$count,$within);
/*
    Find requests within a time scope (from now) that
    match too many remote addresses within a number of seconds
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
        return $this->find ('hpapiSecPwd',$scope,$count,$within);
/*
    Find failed authentications within a time scope (from now) that
    match too many users within a number of seconds
    for the same password
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

    protected function find ($spr,$scope,$count,$within) {
        $uids   = $this->hpapi->dbCall (
            $spr
           ,$this->now - intval ($scope)
           ,$this->now
           ,$count
           ,$within
        );
        return $uids;
    }

    protected function lock ( ) {
        $uids               = '';
        $notfirst           = false;
        foreach ($this->uids as $uid=>$lock)
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
        $this->hpapi->dbCall (
            'hpapiSecLock'
           ,$uids
           ,$this->now + $firstlock
        );
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
        $lines = file (HPAPI_SEC_LOG);
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

