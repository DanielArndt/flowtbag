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
    "math"
)

// Calculates the standard deviation of a feature.
func stddev(sqsum int64, sum int64, count int64) int64 {
    return int64(math.Sqrt(float64(
        (sqsum - (sum*sum)/count) / (count - 1))))
}

// Returns the minimum of two int64
func Min64(i1 int64, i2 int64) int64 {
    if i1 < i2 {
        return i1
    }
    return i2
}

// Returns the minimum of two ints
func MinInt(i1 int, i2 int) int {
    if i1 < i2 {
        return i1
    }
    return i2
}
