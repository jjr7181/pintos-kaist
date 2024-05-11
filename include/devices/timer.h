#ifndef DEVICES_TIMER_H
#define DEVICES_TIMER_H

#include <round.h>
#include <stdint.h>

/* Number of timer interrupts per second. */
#define TIMER_FREQ 100

void timer_init (void);
void timer_calibrate (void);
void thread_sleep(int64_t ticks);
void thread_awake(int64_t ticks);
void minimum_tick_awake(int64_t ticks);
int64_t get_next_tick_to_awake(void);
//위에 추가된 헤더파일 내의 함수들은 스레드를 block->깨어나면 ready로 변경하기 위해 추가한 함수다.

int64_t timer_ticks (void);
int64_t timer_elapsed (int64_t);

void timer_sleep (int64_t ticks);
void timer_msleep (int64_t milliseconds);
void timer_usleep (int64_t microseconds);
void timer_nsleep (int64_t nanoseconds);

void timer_print_stats (void);

#endif /* devices/timer.h */
