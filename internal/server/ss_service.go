package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/network"
)

type SSService struct {
	mu      sync.Mutex
	manager *network.SsManager
	process map[string]context.CancelFunc
}

func NewSSService(manager *network.SsManager) *SSService {
	return &SSService{
		manager: manager,
		process: make(map[string]context.CancelFunc),
	}
}

func (s *SSService) StartAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for name := range s.manager.GetAll() {
		if _, running := s.process[name]; !running {
			if err := s.start(name); err != nil {
				log.Printf("failed to start %s: %v", name, err)
			}
		}
	}
	return nil
}

func (s *SSService) StartOne(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, running := s.process[name]; running {
		return fmt.Errorf("%s already running", name)
	}
	return s.start(name)
}

func (s *SSService) start(name string) error {
	ctx, cancel := context.WithCancel(context.Background())

	s.process[name] = cancel
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.manager.StartSS(ctx, name)
		s.mu.Lock()
		delete(s.process, name)
		s.mu.Unlock()
	}()
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("ss-redir exited (%s): %v", name, err)
		} else {
			log.Printf("ss-redir (%s) exited normally", name)
		}
	case <-time.After(1 * time.Second):
		log.Printf("ss-redir (%s) started successfully", name)
	}
	return nil
}

func (s *SSService) StopOne(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cancel, ok := s.process[name]
	if ok {
		cancel()
		delete(s.process, name)
		log.Printf("stopped: %s", name)

	} else {
		return fmt.Errorf("%s not running", name)
	}
	return nil
}

func (s *SSService) StopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for name, cancel := range s.process {
		cancel()
		log.Printf("stopped: %s", name)
	}
	s.process = make(map[string]context.CancelFunc)
}

func (s *SSService) RestartOne(name string) error {
	if err := s.StopOne(name); err != nil {
		log.Printf("warn: StopOne during restart failed: %v", err)
	}

	for i := 0; i < 10; i++ {
		time.Sleep(100 * time.Millisecond)

		s.mu.Lock()
		_, stillRunning := s.process[name]
		s.mu.Unlock()

		if !stillRunning {
			break
		}
	}

	return s.StartOne(name)
}

func (s *SSService) IsRunning(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.process[name]
	return ok
}
