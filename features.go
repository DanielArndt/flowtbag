/* 
 *  Copyright 2011 Daniel Arndt
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  @author: Daniel Arndt <danielarndt@gmail.com>
 *
 */

package main

import (
	"fmt"
)

// Defines the minimum set of functions needed for a Feature.
type Feature interface {
	Add(int64)      // Add a particular value to a feature
	Export() string // Export the contents of a feature in string form
	Get() int64
	Set(int64) // Reset the feature to a particular value
}

// A feature which takes values and bins them according to their value.
type BinFeature struct {
	num_bins int   // The number of bins for this feature
	bin_sep  int   // Ie. the magnitude of the range contained in each bin
	bins     []int // Stores the actual count for each bin
}

// Initializes the BinFeature to contain bins starting at min and going to max.
// Anything below min is thrown into the lowest bin, and anything above max is
// put in the last bin. num_bins is the number of bins required in the range
// [min, max]
func (f *BinFeature) Init(min int, max int, num_bins int) {
	f.num_bins = num_bins - 1
	diff := max - min
	f.bin_sep = diff / f.num_bins
	f.bins = make([]int, num_bins)
	for i := 0; i < num_bins; i++ {
		f.bins[i] = 0
	}
}

func (f *BinFeature) Add(val int64) {
	bin := MinInt(int(val)/f.bin_sep, f.num_bins)
	f.bins[bin] += 1
}

func (f *BinFeature) Export() string {
	ret := ""
	for i := 0; i < len(f.bins); i++ {
		if i > 0 {
			ret += fmt.Sprintf(",")
		}
		ret += fmt.Sprintf("%d", f.bins[i])
	}
	return ret
}

func (f *BinFeature) Get() int64 {
	return int64(f.bins[0])
}

func (f *BinFeature) Set(val int64) {
	for i := 0; i < len(f.bins); i++ {
		f.bins[i] = int(val)
	}
}

type DistributionFeature struct {
	sum   int64
	sumsq int64
	count int64
	min   int64
	max   int64
}

func (f *DistributionFeature) Init(val int64) {
	f.Set(val)
}

func (f *DistributionFeature) Add(val int64) {
	f.sum += val
	f.sumsq += val * val
	f.count++
	if (val < f.min) || (f.min == 0) {
		f.min = val
	}
	if val > f.max {
		f.max = val
	}
}

func (f *DistributionFeature) Export() string {
	var (
		stdDev int64 = 0
		mean   int64 = 0
	)
	if f.count > 0 {
		stdDev = int64(stddev(float64(f.sumsq), float64(f.sum), f.count))
		mean = f.sum / f.count
	}
	return fmt.Sprintf("%d,%d,%d,%d", f.min, mean, f.max, stdDev)
}

func (f *DistributionFeature) Get() int64 {
	return f.count
}

// Set the DistributionFeature to include val as the single value in the Feature.
func (f *DistributionFeature) Set(val int64) {
	f.sum = val
	f.sumsq = val * val
	f.count = val
	f.min = val
	f.max = val
}

type ValueFeature struct {
	value int64
}

func (f *ValueFeature) Init(val int64) {
	f.Set(val)
}

func (f *ValueFeature) Add(val int64) {
	f.value += val
}

func (f *ValueFeature) Export() string {
	return fmt.Sprintf("%d", f.value)
}

func (f *ValueFeature) Get() int64 {
	return f.value
}

func (f *ValueFeature) Set(val int64) {
	f.value = val
}
