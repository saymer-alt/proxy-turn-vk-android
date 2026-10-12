// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
 "encoding/json"
 "net"
 "net/url"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func qAnonOpts() qOptions {
 return qOptions{Auth:"anonymous",Device:"owner-lab-anon9",DNS:"yandex",MaxWorkers:9}
}

func TestQwdttAnonymousSingleHashNineAdmission(t *testing.T) {
 o:=qAnonOpts()
 c,name,err:=qParse([]byte(qURI("9","oneVKhash")),o,131072)
 if err!=nil || name!="Synthetic" || c.Auth!="anonymous" ||
     c.Workers!=12 || c.CredsFile!="" || c.VK!="oneVKhash" ||
     labValidate(c)!=nil {
     t.Fatal("single-hash anonymous 9 -> internal 12 -> effective 9 rejected")
 }
 if _,_,e:=qParse([]byte(qURI("9","oneVKhash")),o,131071);e==nil || !strings.Contains(e.Error(),"MEMORY_INSUFFICIENT") {
     t.Fatal("128MiB preflight absent")
 }
 badCases:=[]struct{ w,h string; mutate func(*qOptions) }{
     {"18","oneVKhash,twoVKhash",nil},
     {"16","oneVKhash",nil},
     {"12","oneVKhash",nil},
     {"9","oneVKhash,twoVKhash",nil},
     {"9","oneVKhash",func(o *qOptions){o.MaxWorkers=18}},
     {"9","oneVKhash",func(o *qOptions){o.MaxWorkers=4}},
     {"9","oneVKhash",func(o *qOptions){o.Credentials="/tmp/unsafe-creds"}},
 }
 for i,tc:=range badCases {
     x:=o
     if tc.mutate!=nil {tc.mutate(&x)}
     if _,_,e:=qParse([]byte(qURI(tc.w,tc.h)),x,300000);e==nil {
         t.Fatalf("case %d wrongly allowed unsupported anonymous worker/hash policy",i)
     }
 }
 account:=qTestOptions()
 if _,_,e:=qParse([]byte(qURI("9","oneVKhash")),account,300000);e==nil ||
     !strings.Contains(e.Error(),"WORKER_BUDGET_EXCEEDED") {
    t.Fatal("account quota unexpectedly raised")
 }
 badPeer,_:=url.Parse(qURI("9","oneVKhash"))
 vals:=badPeer.Query()
 vals.Set("peer","host.example:56000")
 badPeer.RawQuery=vals.Encode()
 if _,_,e:=qParse([]byte(badPeer.String()),o,300000);e==nil {
    t.Fatal("unapproved public domain peer admitted")
 }
}

func TestQwdttAnonymousPrivateOfflineImport(t *testing.T) {
 d:=t.TempDir()
 if err:=os.Chmod(d,0700);err!=nil{t.Fatal(err)}
 listener,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
 if err!=nil{t.Fatal(err)}
 port:=listener.LocalAddr().(*net.UDPAddr).Port
 listener.Close()
 u,_:=url.Parse(qURI("9","oneVKhash"))
 vals:=u.Query()
 vals.Set("port",fmtInt(port))
 u.RawQuery=vals.Encode()
 input:=filepath.Join(d,"anonymous.uri")
 output:=filepath.Join(d,"anon.json")
 if err:=os.WriteFile(input,[]byte(u.String()+"\n"),0600);err!=nil{t.Fatal(err)}
 o:=qAnonOpts()
 o.Input,o.Output=input,output
 if err:=qImport(o);err!=nil{t.Fatalf("anonymous single-hash offline import failed: %v",err)}
 st,err:=os.Stat(output)
 if err!=nil || st.Mode().Perm()!=0600 {t.Fatal("unsafe generated anonymous config permissions")}
 b,err:=os.ReadFile(output)
 if err!=nil{t.Fatal(err)}
 var data struct{
     Workers int `json:"workers"`
     Auth string `json:"auth"`
     CredsFile string `json:"creds_file"`
     Requested int `json:"qwdtt_requested_workers"`
     Effective int `json:"qwdtt_effective_workers"`
 }
 if json.Unmarshal(b,&data)!=nil || data.Workers!=12 ||
     data.Auth!="anonymous" || data.CredsFile!="" ||
     data.Requested!=9 || data.Effective!=9 {
     t.Fatal("anonymous private output mismatches real runtime's 9-effective map")
 }
 if err:=qImport(o);err==nil {t.Fatal("second import must not overwrite secret file")}
}
