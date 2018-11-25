#!/bin/bash

n=1000
while [ $n -ne 0 ]
do
	./gtest sw3
	echo n=$n
	n=`expr $n - 1`
done
