package configuration

import (
	"encoding/json"
	"io"
	"time"

	"github.com/Symantec/Dominator/lib/configwatch"
	"github.com/Symantec/Dominator/lib/log"
)

func watch(configUrl string, checkInterval time.Duration,
	logger log.DebugLogger) (<-chan *Configuration, error) {
	configChannel := make(chan *Configuration, 1)
	rawChannel, err := configwatch.Watch(configUrl, checkInterval, decode,
		logger)
	if err != nil {
		return nil, err
	}
	go watchLoop(configChannel, rawChannel)
	return configChannel, nil
}

func watchLoop(configChannel chan<- *Configuration,
	rawChannel <-chan interface{}) {
	for data := range rawChannel {
		configChannel <- data.(*Configuration)
	}
	close(configChannel)
}

func decode(reader io.Reader) (interface{}, error) {
	var config Configuration
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}
