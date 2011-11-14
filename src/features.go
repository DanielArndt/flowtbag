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
    "math"
    vector "container/vector"
)

func stddev(sqsum int64, sum int64, count int64) int64 {
    return int64(math.Sqrt(float64(
        (sqsum - (sum*sum)/count) / (count - 1))))
}

func Min64(i1 int64, i2 int64) int64 {
    if i1 < i2 {
        return i1
    }
    return i2
}

func MinInt(i1 int, i2 int) int {
    if i1 < i2 {
        return i1
    }
    return i2
}

type Feature interface {
    Add(int64)
    Export() string
    Set(int64)
}

type BinFeature struct {
    num_bins int // The number of bins for this feature
    bin_sep  int // The separator for each bin. Ie. the magnitude of the range
    // of each bin
    bins vector.IntVector // The actual values of each bin.
}

func (f *BinFeature) Init(min int, max int, num_bins int) {
    f.num_bins = num_bins - 1
    diff := max - min
    f.bin_sep = diff / f.num_bins
    f.bins = make(vector.IntVector, num_bins)
    for i := 0; i < num_bins; i++ {
        f.bins.Set(i, 0)
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
    //	ret += "]"
    return ret
}

func (f *BinFeature) Set(val int64) {
    for i := 0; i < len(f.bins); i++ {
        f.bins[i] = int(val)
    }
}

type DistFeature struct {
    sum   int64
    sumsq int64
    count int64
    min   int64
    max   int64
}

func (f *DistFeature) Init(val int64) {
    f.Set(val)
}

func (f *DistFeature) Add(val int64) {
    f.sum += val
    f.sumsq += val * val
    f.count++
    if val < f.min {
        f.min = val
    }
    if val > f.max {
        f.max = val
    }
}

func (f *DistFeature) Export() string {
    return fmt.Sprintf("%d,%d,%d,%d", f.min, f.sum/f.count, f.max,
        stddev(f.sumsq, f.sum, f.count))
}

// Set the DistFeature to include val as the single value in the Feature.
func (f *DistFeature) Set(val int64) {
    f.sum = val
    f.sumsq = val * val
    f.count = 1
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
    return string(f.value)
}

func (f *ValueFeature) Set(val int64) {
    f.value = val
}
