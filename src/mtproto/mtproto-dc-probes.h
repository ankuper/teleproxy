/*
    DC latency probes — periodic TCP handshake measurement to Telegram DCs.

    Teleproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

#pragma once

#include "common/common-stats.h"

/* Initialize the DC probe subsystem.
   interval_seconds > 0 enables probes; 0 disables.
   Call once from master process after fork. */
void dc_probes_init (int interval_seconds);

/* Called from cron() every second.  Starts a new probe round
   when the configured interval elapses. */
void dc_probes_cron (void);

/* Called from precise_cron() every event loop iteration.
   Polls pending non-blocking connects.  No-op when no probes
   are in flight. */
void dc_probes_check (void);

/* Append Prometheus histogram / counter / gauge lines to sb. */
void dc_probes_write_prometheus (stats_buffer_t *sb);

/* Append human-readable text stats to sb. */
void dc_probes_write_text_stats (stats_buffer_t *sb);
