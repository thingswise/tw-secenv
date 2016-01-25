package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("secenv")

// Example format string. Everything except the message has a custom color
// which is dependent on the log level. Many fields have a custom output
// formatting too, eg. the time returns the hour down to the milli second.
var format = logging.MustStringFormatter(
	"%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}",
)

var (
	debug     = flag.Bool("v", false, "verbose output")
	keyType   = flag.String("t", "symmetric", "exported key type")
	secConfig = flag.String("f", "sec-config.json", "global security config file")
	interval  = flag.Int("i", 15, "security config file refresh interval (sec)")
)

var Usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s [options] KEY_NAME COMMAND...\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  KEY_NAME - the name of the key entry to monitor\n")
	fmt.Fprintf(os.Stderr, "  COMMAND  - shell command to execute\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = Usage
	flag.Parse()

	logging.SetFormatter(format)
	if *debug {
		logging.SetLevel(logging.DEBUG, "secenv")
	} else {
		logging.SetLevel(logging.ERROR, "secenv")
	}

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		s := <-sc
		ssig := s.(syscall.Signal)
		log.Error("Signal received: %s", ssig.String())
		os.Exit(128 + int(ssig))
	}()

	if flag.NArg() < 2 {
		Usage()
		os.Exit(2)
	}

	keyName := flag.Arg(0)
	cmd := flag.Args()[1:]

	ctx := &Context{
		keyName: keyName,
		cmd:     cmd,
	}

	ctx.Loop()

}

type Context struct {
	keyName string
	cmd     []string

	currentKey Key
	process    *Process
}

type Process struct {
	cmd  *exec.Cmd
	exit chan int
}

func NewProcess(cmd string, args ...string) *Process {
	_cmd := exec.Command(cmd, args...)
	_cmd.Stdout = os.Stdout
	_cmd.Stderr = os.Stderr
	return &Process{
		cmd:  _cmd,
		exit: make(chan int, 1),
	}
}

func (p *Process) ApplyEnv(key Key) {
	p.cmd.Env = os.Environ()
	for k, v := range key.Env() {
		p.cmd.Env = append(p.cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
}

func (p *Process) Start() error {
	if err := p.cmd.Start(); err != nil {
		return err
	}

	go func() {
		err := p.cmd.Wait()
		if err != nil {
			switch _err := err.(type) {
			case *exec.ExitError:
				w, _ := _err.Sys().(syscall.WaitStatus)
				p.exit <- w.ExitStatus()
			default:
				p.exit <- 128
			}
		} else {
			p.exit <- 0
		}
	}()

	return nil
}

func (p *Process) Kill() error {
	return p.cmd.Process.Kill()
}

func (p *Process) Signal(sig os.Signal) (chan int, error) {
	if err := p.cmd.Process.Signal(sig); err != nil {
		return nil, err
	}

	return p.exit, nil
}

func (c *Context) Loop() {
	for {
		key, err := readKey(c.keyName)
		if err != nil {
			log.Error("Error reading key %s: %s", c.keyName, err)
			time.Sleep(time.Duration(*interval) * time.Second)
			continue
		}

		if c.currentKey != nil {
			same, err := c.currentKey.Compare(key)
			if err != nil {
				panic(err)
			}

			if same && c.process != nil {
				time.Sleep(time.Duration(*interval) * time.Second)
				continue
			}
		}

		if c.process != nil {
			ch, _ := c.process.Signal(syscall.SIGTERM)
			w := make(chan bool, 1)
			go func() {
				time.Sleep(5 * time.Second)
				w <- true
			}()

			select {
			case <-ch:
			case <-w:
				c.process.Kill()
			}
		}

		c.currentKey = key
		c.process = NewProcess(c.cmd[0], c.cmd[1:]...)
		c.process.ApplyEnv(c.currentKey)

		if err := c.process.Start(); err != nil {
			log.Error("Cannot start process: %s", err)
		}
		time.Sleep(time.Duration(*interval) * time.Second)
	}

}

type Key interface {
	Compare(other Key) (bool, error)
	Env() map[string]string
}

type SymmetricKey struct {
	key    string
	secret string
}

func NewSymmetricKey(cfg *map[string]interface{}) (*SymmetricKey, error) {
	var expiration int64 = 0
	_expiration, ok := (*cfg)["expiration"]
	if ok {
		exp, ok := _expiration.(float64)
		if !ok {
			return nil, fmt.Errorf("Invalid expiration value")
		} else {
			expiration = int64(exp)
		}
	}

	if expiration != 0 && expiration <= time.Now().Unix()+int64(*interval) {
		return nil, fmt.Errorf("Key expired")
	}

	_key, ok := (*cfg)["key"]
	if !ok {
		return nil, fmt.Errorf("Cannot find key value")
	}

	key, ok := _key.(string)
	if !ok {
		return nil, fmt.Errorf("Invalid key value")
	}

	_secret, ok := (*cfg)["secret"]
	if !ok {
		return nil, fmt.Errorf("Cannot find secret value")
	}

	secret, ok := _secret.(string)
	if !ok {
		return nil, fmt.Errorf("Invalid secret value")
	}

	return &SymmetricKey{key: key, secret: secret}, nil
}

func (s *SymmetricKey) Compare(other Key) (bool, error) {
	s_other, ok := other.(*SymmetricKey)
	if !ok {
		return false, fmt.Errorf("Key type changed on the fly")
	} else {
		return s.key == s_other.key && s.secret == s_other.secret, nil
	}
}

func (s *SymmetricKey) Env() map[string]string {
	result := make(map[string]string)
	result["KEY"] = s.key
	result["SECRET"] = s.secret
	return result
}

func readKey(keyName string) (Key, error) {
	data, err := ioutil.ReadFile(*secConfig)
	if err != nil {
		return nil, err
	}

	var cfg map[string]interface{} = make(map[string]interface{})
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	_keyRef, ok := cfg[keyName]
	if ok {
		keyRefArr, ok := _keyRef.([]interface{})
		if ok {
			if len(keyRefArr) > 0 {
				for _, _keyRef1 := range keyRefArr {
					keyRef, ok := _keyRef1.(map[string]interface{})
					if !ok {
						log.Debug("1")
						continue
					}

					_groupRef, ok := keyRef["group"]
					if !ok {
						log.Debug("key %s: No group name", keyName)
						continue
					}

					groupRef, ok := _groupRef.(string)
					if !ok {
						log.Debug("2")
						continue
					}

					_group, ok := cfg[groupRef]
					if !ok {
						log.Debug("key %s: No group", keyName)
						continue
					}

					group, ok := _group.(map[string]interface{})
					if !ok {
						log.Debug("3")
						continue
					}

					_keyName, ok := keyRef["name"]
					if !ok {
						log.Debug("key %s: No key name", keyName)
						continue
					}

					keyName, ok := _keyName.(string)
					if !ok {
						log.Debug("4")
						continue
					}

					_keyCfg, ok := group[keyName]
					if !ok {
						log.Debug("key %s: No key", keyName)
						continue
					}

					keyCfg, ok := _keyCfg.(map[string]interface{})
					if !ok {
						log.Debug("5")
						continue
					}

					switch *keyType {
					case "symmetric":
						key, err := NewSymmetricKey(&keyCfg)
						if err != nil {
							log.Debug("key %s: key parsing error: %s", keyName, err.Error())
							continue
						}

						return key, nil
					default:
						log.Debug("key %s: Unsupported key type: %s", keyName, *keyType)
						continue
					}
				}
			}
			return nil, fmt.Errorf("No valid key configuration found for key %s", keyName)
		} else {
			return nil, fmt.Errorf("Invalid key reference list for key %s", keyName)
		}
	} else {
		return nil, fmt.Errorf("Key %s cat", keyName)
	}
}

func runForever() {
	for {

	}
}
