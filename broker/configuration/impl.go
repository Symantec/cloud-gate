package configuration

import (
	"io"
	"time"

	"github.com/Cloud-Foundations/Dominator/lib/configwatch"
	"github.com/Cloud-Foundations/Dominator/lib/log"
	"github.com/Symantec/cloud-gate/lib/constants"
	"gopkg.in/yaml.v2"
)

func watch(configUrl string, cacheFilename string, checkInterval time.Duration,
	logger log.DebugLogger) (<-chan *Configuration, error) {
	configChannel := make(chan *Configuration, 1)
	rawChannel, err := configwatch.WatchWithCache(configUrl, checkInterval, decode,
		cacheFilename, constants.InitialTimeoutForAccountInfo,
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
	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}
