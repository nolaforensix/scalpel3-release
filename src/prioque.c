//
// Implementation of prioque priority queue functions (c) 1985-2026 Golden
// G. Richard III, Ph.D. (@nolaforensix).
//

#include "prioque.h"

#define QUEUE_MAGIC 0xC0FFEEC0FFEE

void init_queue(Queue *q, uint32_t elementsize, bool duplicates,
                int (*compare)(const void *e1, const void *e2),
                bool priority_is_tag_only) {
  q->magic = QUEUE_MAGIC;
  atomic_init(&q->queuelength, 0);
  q->elementsize = elementsize;
  q->queue = NULL;
  q->previous = NULL;
  q->tail = NULL;
  q->current = NULL;
  q->duplicates = duplicates;
  q->compare = compare;
  q->priority_is_tag_only = priority_is_tag_only;
  nolock_rewind_queue(q);
  pthread_mutex_init(&q->lock, NULL);
}


bool queue_initialized(Queue q) {
  return q.magic == QUEUE_MAGIC;
}


void nolock_destroy_queue(Queue *q) {
  Queue_element temp;

  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(
        stderr,
        "** QUEUE NOT INITIALIZED in prioque.c nolock_destroy_queue() **\n");
    exit(1);
  }

  atomic_store_explicit(&q->queuelength, 0, memory_order_release);

  while (q->queue != NULL) {
    temp = q->queue;
    q->queue = q->queue->next;
    free(temp->info);
    free(temp);
  }

  q->previous = NULL;
  q->current = NULL;
  q->tail = NULL;
}


void destroy_queue(Queue *q) {
  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c destroy_queue() **\n");
    exit(1);
  }

  pthread_mutex_lock(&q->lock);
  nolock_destroy_queue(q);
  pthread_mutex_unlock(&q->lock);
}


void *nolock_element_in_queue(Queue *q, void *element) {
  void *found = NULL;

  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(
        stderr,
        "** QUEUE NOT INITIALIZED in prioque.c nolock_element_in_queue() **\n");
    exit(1);
  }

  if (! element) {
    fprintf(stderr, "** NULL pointer for element in prioque.c "
                    "nolock_element_in_queue() **\n");
    exit(1);
  }

  if (! q->compare) {
    fprintf(stderr, "prioque.c:element_in_queue() can be called only if a "
                    "comparison function was\n"
                    "specified in init_queue().\n");
    exit(1);
  }

  if (q->queue != NULL) {
    nolock_rewind_queue(q);
    while (! nolock_end_of_queue(q) && ! found) {
      if (q->compare(element, q->current->info) == 0) {
        found = q->current->info;
      }
      else {
        nolock_next_element(q);
      }
    }
  }

  if (! found) {
    nolock_rewind_queue(q);
  }

  return found;
}


void *element_in_queue(Queue *q, void *element) {
  void *found;

  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c element_in_queue() **\n");
    exit(1);
  }

  if (! element) {
    fprintf(stderr,
            "** NULL pointer for element in prioque.c element_in_queue() **\n");
    exit(1);
  }

  pthread_mutex_lock(&q->lock);
  found = nolock_element_in_queue(q, element);
  pthread_mutex_unlock(&q->lock);

  return found;
}


bool nolock_delete_from_queue(Queue *q, void *element) {
  bool found = false;

  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c delete_from_queue() **\n");
    exit(1);
  }

  if (! element) {
    fprintf(
        stderr,
        "** NULL pointer for element in prioque.c delete_from_queue() **\n");
    exit(1);
  }

  if (! q->compare) {
    fprintf(stderr, "prioque.c:delete_from_queue() can be called only if a "
                    "comparison function was\n"
                    "specified in init_queue().\n");
    exit(1);
  }

  found = nolock_element_in_queue(q, element);

  if (found) {
    nolock_delete_current(q);
  }

  return found;
}


bool delete_from_queue(Queue *q, void *element) {
  bool found;

  pthread_mutex_lock(&q->lock);
  found = nolock_delete_from_queue(q, element);
  pthread_mutex_unlock(&q->lock);

  return found;
}


void nolock_add_to_queue(Queue *q, void *element, int64_t priority) {
  Queue_element new_element = NULL;
  Queue_element ptr = NULL;
  Queue_element prev = NULL;

  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c add_to_queue() **\n");
    exit(1);
  }

  if (! element) {
    fprintf(stderr,
            "** NULL pointer for element in prioque.c add_to_queue() **\n");
    exit(1);
  }

  if (! q->compare && ! q->duplicates) {
    fprintf(stderr, "prioque.c: If duplicates are disallowed, the comparison "
                    "function must be\n"
                    "specified in init_queue().\n");
    exit(1);
  }

  if (! q->queue ||
      (q->queue && (q->duplicates || ! nolock_element_in_queue(q, element)))) {
    new_element = (Queue_element)malloc(sizeof(struct _Queue_element));
    if (new_element == NULL) {
      fprintf(stderr, "malloc() failed in prioque.c add_to_queue()\n");
      exit(1);
    }

    new_element->info = malloc(q->elementsize);
    if (new_element->info == NULL) {
      fprintf(stderr, "malloc() failed in prioque.c add_to_queue()\n");
      exit(1);
    }

    memcpy(new_element->info, element, q->elementsize);
    new_element->priority = priority;

    if (q->queue == NULL) {  // first element
      new_element->next = NULL;
      q->queue = new_element;
      q->tail = new_element;
    }
    else if (q->priority_is_tag_only) {  // FIFO queue
      new_element->next = NULL;
      q->tail->next = new_element;
      q->tail = new_element;
    }
    else {  // priority queue
      ptr = q->queue;
      while (ptr != NULL && priority <= ptr->priority) {
        prev = ptr;
        ptr = ptr->next;
      }

      if (! prev) {  // new element is first
        new_element->next = q->queue;
        q->queue = new_element;
      }
      else {  // insert new element
        new_element->next = prev->next;
        prev->next = new_element;
        if (new_element->next == NULL) {
          // new tail
          q->tail = new_element;
        }
      }
    }

    nolock_rewind_queue(q);

    atomic_fetch_add_explicit(&q->queuelength, 1, memory_order_acq_rel);
  }
}


void nolock_add_to_queue_priority_relaxed(Queue *q, void *element,
                                          int64_t priority) {
  Queue_element new_element = NULL;
  Queue_element ptr = NULL;
  Queue_element prev = NULL;

  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr, "** QUEUE NOT INITIALIZED in prioque.c "
                    "add_to_queue_priority_relaxed() **\n");
    exit(1);
  }

  if (! element) {
    fprintf(stderr, "** NULL pointer for element in prioque.c "
                    "add_to_queue_priority_relaxed() **\n");
    exit(1);
  }

  if (! q->compare && ! q->duplicates) {
    fprintf(stderr, "prioque.c nolock_add_to_queue_priority_relaxed(): If "
                    "duplicates are disallowed, the comparison\n"
                    "function must be specified in init_queue().\n");
    exit(1);
  }

  if (! q->queue ||
      (q->queue && (q->duplicates || ! nolock_element_in_queue(q, element)))) {
    new_element = (Queue_element)malloc(sizeof(struct _Queue_element));
    if (new_element == NULL) {
      fprintf(stderr, "malloc() failed in prioque.c add_to_queue_priority_relaxed()\n");
      exit(1);
    }

    new_element->info = malloc(q->elementsize);
    if (new_element->info == NULL) {
      fprintf(stderr, "malloc() failed in prioque.c add_to_queue_priority_relaxed()\n");
      exit(1);
    }

    memcpy(new_element->info, element, q->elementsize);
    new_element->priority = priority;

    if (q->queue == NULL) {  // first element
      new_element->next = NULL;
      q->queue = new_element;
      q->tail = new_element;
    }
    else if (q->priority_is_tag_only) {  // FIFO queue
      new_element->next = NULL;
      q->tail->next = new_element;
      q->tail = new_element;
    }
    else {
      // priority queue with relaxed semantics
      if (priority > q->queue->priority) {
        // fast-path head: strictly higher priority than current head
	new_element->next = q->queue;
        q->queue = new_element;
        // tail unchanged
      }
      else if (q->tail && priority <= q->tail->priority) {
        // fast-path tail: <= current tail's priority
        new_element->next = NULL;
        q->tail->next = new_element;
        q->tail = new_element;
      }
      else {
	ptr = q->queue;
        while (ptr != NULL && priority < ptr->priority) {
          prev = ptr;
          ptr = ptr->next;
        }

	if (! prev) {  // new element is first
          new_element->next = q->queue;
          q->queue = new_element;
	}
	else {  // insert new element
          new_element->next = prev->next;
          prev->next = new_element;
          if (new_element->next == NULL) {
            // new tail
            q->tail = new_element;
          }
	}
      }
    }

    nolock_rewind_queue(q);

    atomic_fetch_add_explicit(&q->queuelength, 1, memory_order_acq_rel);
  }
}


void add_to_queue(Queue *q, void *element, int64_t priority) {
  pthread_mutex_lock(&q->lock);
  nolock_add_to_queue(q, element, priority);
  pthread_mutex_unlock(&q->lock);
}


void add_to_queue_priority_relaxed(Queue *q, void *element, int64_t priority) {
  pthread_mutex_lock(&q->lock);
  nolock_add_to_queue_priority_relaxed(q, element, priority);
  pthread_mutex_unlock(&q->lock);
}


void *nolock_nosync_remove_from_front(Queue *q, void *element) {
  Queue_element temp;
  void *ret = NULL;

  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr, "** QUEUE NOT INITIALIZED in prioque.c "
                    "nolock_nosync_remove_from_front() **\n");
    exit(1);
  }

  if (! element) {
    fprintf(stderr, "** NULL pointer for element in prioque.c "
                    "nolock_nosync_remove_from_front() **\n");
    exit(1);
  }

  if (q->queue) {
    memcpy(element, q->queue->info, q->elementsize);
    ret = element;
    temp = q->queue;
    q->queue = q->queue->next;
    free(temp->info);
    free(temp);
    if (q->queue == NULL || q->queue->next == NULL) {
      // new tail
      q->tail = q->queue;
    }
    atomic_fetch_add_explicit(&q->queuelength, -1, memory_order_acq_rel);
    nolock_rewind_queue(q);
  }

  return ret;
}


void *remove_from_front(Queue *q, void *element) {
  void *ret = NULL;

  pthread_mutex_lock(&q->lock);
  ret = nolock_nosync_remove_from_front(q, element);
  pthread_mutex_unlock(&q->lock);

  return ret;
}


void *remove_from_front_sync(Queue *q, void *element, atomic_uint *j,
                             int32_t change) {
  void *ret = NULL;

  atomic_fetch_add_explicit(j, change, memory_order_acq_rel);

  pthread_mutex_lock(&q->lock);

  ret = nolock_nosync_remove_from_front(q, element);

  if (! ret) {
    atomic_fetch_add_explicit(j, change * -1, memory_order_acq_rel);
  }

  pthread_mutex_unlock(&q->lock);

  return ret;
}


bool nolock_empty_queue(Queue *q) {
  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr, "** QUEUE NOT INITIALIZED in prioque.c empty_queue() **\n");
    exit(1);
  }

  return atomic_load_explicit(&q->queuelength, memory_order_acquire) == 0;
}


bool empty_queue(Queue *q) {
  return nolock_empty_queue(q);
}


void *nolock_peek_at_current(Queue *q, void *element, int64_t *priority) {
  void *ret = NULL;

  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c peek_at_current() **\n");
    exit(1);
  }

  if (! element) {
    fprintf(stderr,
            "** NULL pointer for element in prioque.c peek_at_current() **\n");
    exit(1);
  }

  if (q->queue && q->current) {
    memcpy(element, (q->current)->info, q->elementsize);
    ret = element;
    if (priority) {
      *priority = (q->current)->priority;
    }
  }

  return ret;
}


void *peek_at_current(Queue *q, void *element, int64_t *priority) {
  void *ret = NULL;

  pthread_mutex_lock(&q->lock);
  ret = nolock_peek_at_current(q, element, priority);
  pthread_mutex_unlock(&q->lock);

  return ret;
}


void *nolock_pointer_to_current(Queue *q) {
  void *data = NULL;

  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c pointer_to_current() **\n");
    exit(1);
  }

  if (q->queue && q->current) {
    data = (q->current)->info;
  }

  return data;
}


void *pointer_to_current(Queue *q) {
  void *data = NULL;

  pthread_mutex_lock(&q->lock);
  data = nolock_pointer_to_current(q);
  pthread_mutex_unlock(&q->lock);

  return data;
}


int64_t nolock_current_priority(Queue *q) {
  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c current_priority() **\n");
    exit(1);
  }

  if (q->queue == NULL || q->current == NULL) {
    fprintf(stderr, "** NULL pointer in prioque.c current_priority() **\n");
    exit(1);
  }

  return q->current->priority;
}


int64_t current_priority(Queue *q) {
  int64_t priority;

  pthread_mutex_lock(&q->lock);
  priority = nolock_current_priority(q);
  pthread_mutex_unlock(&q->lock);

  return priority;
}


void nolock_update_current(Queue *q, void *element) {
  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c update_current() **\n");
    exit(1);
  }

  if (q->queue == NULL || q->current == NULL || ! element) {
    fprintf(stderr, "** NULL pointer in prioque.c update_current() **\n");
    exit(1);
  }

  memcpy(q->current->info, element, q->elementsize);
}


void update_current(Queue *q, void *element) {
  pthread_mutex_lock(&q->lock);
  nolock_update_current(q, element);
  pthread_mutex_unlock(&q->lock);
}


void nolock_delete_current(Queue *q) {
  Queue_element temp;

  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(
        stderr,
        "** QUEUE NOT INITIALIZED in prioque.c nolock_delete_current() **\n");
    exit(1);
  }

  if (q->queue == NULL || q->current == NULL) {
    fprintf(
        stderr,
        "** NULL pointer in prioque prioque.c nolock_delete_current() **\n");
    exit(1);
  }

  temp = q->current;

  if (q->previous == NULL) {  // deletion at beginning
    q->queue = q->queue->next;
    q->current = q->queue;
    if (q->queue == NULL || q->queue->next == NULL) {
      // new tail
      q->tail = q->queue;
    }
  }
  else {  // internal deletion
    q->previous->next = q->current->next;
    q->current = q->previous->next;

    if (q->tail == temp) {
      // new tail
      q->tail = q->previous;
    }
  }

  free(temp->info);
  free(temp);

  atomic_fetch_add_explicit(&q->queuelength, -1, memory_order_acq_rel);
}


void delete_current(Queue *q) {
  pthread_mutex_lock(&q->lock);
  nolock_delete_current(q);
  pthread_mutex_unlock(&q->lock);
}


bool nolock_end_of_queue(Queue *q) {
  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c end_of_queue() **\n");
    exit(1);
  }

  return q->current == NULL;
}


bool end_of_queue(Queue *q) {
  bool ret;

  pthread_mutex_lock(&q->lock);
  ret = nolock_end_of_queue(q);
  pthread_mutex_unlock(&q->lock);

  return ret;
}


void nolock_next_element(Queue *q) {
  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c next_element() **\n");
    exit(1);
  }

  if (q->queue == NULL) {
    fprintf(stderr, "** NULL pointer in prioque.c next_element() **\n");
    exit(1);
  }
  else if (q->current == NULL) {
    fprintf(
        stderr,
        "** Advance past end--NULL pointer in prioque.c next_element() **\n");
    exit(1);
  }

  q->previous = q->current;
  q->current = q->current->next;
}


void next_element(Queue *q) {
  pthread_mutex_lock(&q->lock);
  nolock_next_element(q);
  pthread_mutex_unlock(&q->lock);
}


void nolock_rewind_queue(Queue *q) {
  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c rewind_queue() **\n");
    exit(1);
  }

  q->current = q->queue;
  q->previous = NULL;
}


void rewind_queue(Queue *q) {
  pthread_mutex_lock(&q->lock);
  nolock_rewind_queue(q);
  pthread_mutex_unlock(&q->lock);
}


uint64_t nolock_queue_length(Queue *q) {
  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c queue_length() **\n");
    exit(1);
  }

  return atomic_load_explicit(&q->queuelength, memory_order_acquire);
}


uint64_t queue_length(Queue *q) {
  return nolock_queue_length(q);
}


void copy_queue(Queue *q1, Queue *q2) {
  if (! q1 || q1->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** FIRST QUEUE NOT INITIALIZED in prioque.c copy_queue() **\n");
    exit(1);
  }

  if (! q2 || q2->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** SECOND QUEUE NOT INITIALIZED in prioque.c copy_queue() **\n");
    exit(1);
  }

  // to avoid deadlock, this function acquires locks in queue memory address
  // order lock q1, q2
  if (q1 < q2) {
    pthread_mutex_lock(&(q1->lock));
    pthread_mutex_lock(&(q2->lock));
  }
  else {
    pthread_mutex_lock(&(q2->lock));
    pthread_mutex_lock(&(q1->lock));
  }

  // free elements in q1 before copy

  nolock_destroy_queue(q1);

  // now make q1 a clone of q2

  atomic_store_explicit(&q1->queuelength, 0, memory_order_release);
  q1->elementsize = q2->elementsize;
  q1->queue = NULL;
  q1->tail = NULL;
  q1->duplicates = q2->duplicates;
  q1->priority_is_tag_only = q2->priority_is_tag_only;
  q1->compare = q2->compare;

  nolock_rewind_queue(q2);
  while (! nolock_end_of_queue(q2)) {
    nolock_add_to_queue(q1, nolock_pointer_to_current(q2),
                        nolock_current_priority(q2));
    nolock_next_element(q2);
  }

  nolock_rewind_queue(q1);
  nolock_rewind_queue(q2);

  // unlock queues
  if (q1 > q2) {
    pthread_mutex_unlock(&(q1->lock));
    pthread_mutex_unlock(&(q2->lock));
  }
  else {
    pthread_mutex_unlock(&(q2->lock));
    pthread_mutex_unlock(&(q1->lock));
  }
}


bool equal_queues(Queue *q1, Queue *q2) {
  Queue_element temp1, temp2;
  bool same = true;

  if (! q1 || q1->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** FIRST QUEUE NOT INITIALIZED in prioque.c equal_queues() **\n");
    exit(1);
  }

  if (! q2 || q2->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** SECOND QUEUE NOT INITIALIZED in prioque.c equal_queues() **\n");
    exit(1);
  }

  if (! q1->compare || ! q2->compare || q1->compare != q2->compare) {
    fprintf(
        stderr,
        "** INCONSISTENT COMPARE FUNCTIONS in prioque.c equal_queues() **\n");
    exit(1);
  }

  // to avoid deadlock, this function acquires locks in queue memory address
  // order lock q1, q2
  if (q1 < q2) {
    pthread_mutex_lock(&(q1->lock));
    pthread_mutex_lock(&(q2->lock));
  }
  else {
    pthread_mutex_lock(&(q2->lock));
    pthread_mutex_lock(&(q1->lock));
  }

  if (atomic_load_explicit(&q1->queuelength, memory_order_acquire) !=
          atomic_load_explicit(&q2->queuelength, memory_order_acquire) ||
      q1->elementsize != q2->elementsize) {
    same = false;
  }
  else {
    temp1 = q1->queue;
    temp2 = q2->queue;
    while (same && temp1 != NULL) {
      same = q1->compare(temp1->info, temp2->info) == 0 &&
             temp1->priority == temp2->priority;
      temp1 = temp1->next;
      temp2 = temp2->next;
    }
  }

  // unlock queues
  if (q1 > q2) {
    pthread_mutex_unlock(&(q1->lock));
    pthread_mutex_unlock(&(q2->lock));
  }
  else {
    pthread_mutex_unlock(&(q2->lock));
    pthread_mutex_unlock(&(q1->lock));
  }

  return same;
}


void merge_queues(Queue *q1, Queue *q2) {
  Queue_element temp;

  if (! q1 || q1->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** FIRST QUEUE NOT INITIALIZED in prioque.c merge_queues() **\n");
    exit(1);
  }

  if (! q2 || q2->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** SECOND QUEUE NOT INITIALIZED in prioque.c merge_queues() **\n");
    exit(1);
  }

  // to avoid deadlock, this function acquires locks in queue memory address
  // order lock q1, q2
  if (q1 < q2) {
    pthread_mutex_lock(&(q1->lock));
    pthread_mutex_lock(&(q2->lock));
  }
  else {
    pthread_mutex_lock(&(q2->lock));
    pthread_mutex_lock(&(q1->lock));
  }

  temp = q2->queue;

  while (temp != NULL) {
    nolock_add_to_queue(q1, temp->info, temp->priority);
    temp = temp->next;
  }

  nolock_rewind_queue(q1);

  // unlock queues
  if (q1 > q2) {
    pthread_mutex_unlock(&(q1->lock));
    pthread_mutex_unlock(&(q2->lock));
  }
  else {
    pthread_mutex_unlock(&(q2->lock));
    pthread_mutex_unlock(&(q1->lock));
  }
}


bool serialize_queue(Queue *q,
                     bool (*serialize_element)(void **element,
                                               int64_t *priority, FILE *fp,
                                               StateSerialization mode),
                     FILE *fp) {
  bool ok = true;

  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c serialize_queue() **\n");
    exit(1);
  }

  if (! fp) {
    fprintf(stderr, "** NULL fp in prioque.c serialize_queue() **\n");
    exit(1);
  }

  if (! serialize_element) {
    fprintf(
        stderr,
        "** NULL serialization function in prioque.c serialize_queue() **\n");
    exit(1);
  }

  pthread_mutex_lock(&q->lock);

  // write count
  uint64_t num =
      (uint64_t)atomic_load_explicit(&q->queuelength, memory_order_acquire);
  if (fwrite(&num, sizeof(num), 1, fp) != 1) {
    pthread_mutex_unlock(&q->lock);
    ok = false;
    goto done;
  }

  // iterate elements
  nolock_rewind_queue(q);
  while (ok && ! nolock_end_of_queue(q)) {
    int64_t pr = nolock_current_priority(q);

    // Pass a pointer to the SLOT pointer: *slot_ptr == address of the element
    // bytes
    void *slot = nolock_pointer_to_current(q);
    ok = serialize_element(&slot, &pr, fp, SERIALIZE);

    nolock_next_element(q);
  }

  nolock_rewind_queue(q);
  fflush(fp);

done:
  pthread_mutex_unlock(&q->lock);
  return ok;
}


bool serialize_queue_h(Queue *q,
                       bool (*serialize_element)(void **element,
                                                 int64_t *priority, FILE *fp,
                                                 StateSerialization mode),
                       int handle) {
  if (handle < 0) {
    return false;
  }

  int h = dup(handle);

  if (h < 0) {
    return false;
  }

  FILE *fp = fdopen(h, "wb");

  if (! fp) {
    close(h);
    return false;
  }

  bool ok = serialize_queue(q, serialize_element, fp);

  fclose(fp);

  return ok;
}


bool deserialize_queue(Queue *q,
                       bool (*deserialize_element)(void **, int64_t *, FILE *,
                                                   StateSerialization),
                       bool relaxed_priority, FILE *fp) {
  bool ok = true;
  uint64_t num_elements = 0;
  void *arg;
  void *slot;

  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c deserialize_queue() **\n");
    exit(1);
  }

  if (! fp) {
    fprintf(stderr, "** NULL fp in prioque.c deserialize_queue() **\n");
    exit(1);
  }

  if (! deserialize_element) {
    fprintf(
        stderr,
        "** NULL serialization function in prioque.c deserialize_queue() **\n");
    exit(1);
  }

  pthread_mutex_lock(&q->lock);

  // read element count
  if (fread(&num_elements, sizeof(num_elements), 1, fp) != 1) {
    perror("couldn't deserialize number of elements");
    ok = false;
    goto done;
  }

  for (uint64_t i = 0; i < num_elements; i++) {
    int64_t pr = 0;

    // preallocate a slot so slot-based callbacks can write into it
    slot = malloc(q->elementsize);
    if (slot == NULL) {
      fprintf(stderr, "malloc() failed in prioque.c deserialize_queue()\n");
      exit(1);
    }

    arg = slot;  // what we actually pass to the callback

    ok = deserialize_element(&arg, &pr, fp, DESERIALIZE);

    if (! ok) {
      free(slot);
      ok = false;
      goto done;
    }

    // if the callback returned a different buffer, free our unused slot
    if (arg != slot) {
      free(slot);
    }

    if (relaxed_priority) {
      nolock_add_to_queue_priority_relaxed(q, arg, pr);
    }
    else {
      nolock_add_to_queue(q, arg, pr);
    }

    free(arg);
  }

  nolock_rewind_queue(q);

done:
  pthread_mutex_unlock(&q->lock);

  return ok;
}


bool deserialize_queue_h(Queue *q,
                         bool (*deserialize_element)(void **element,
                                                     int64_t *priority,
                                                     FILE *fp,
                                                     StateSerialization mode),
                         bool relaxed_priority, int handle) {
  if (handle < 0) {
    return false;
  }

  int h = dup(handle);

  if (h < 0) {
    return false;
  }

  FILE *fp = fdopen(h, "rb");

  if (! fp) {
    close(h);
    return false;
  }

  bool ok = deserialize_queue(q, deserialize_element, relaxed_priority, fp);

  fclose(fp);

  return ok;
}


void lock_queue(Queue *q) {
  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr, "** QUEUE NOT INITIALIZED in prioque.c lock_queue() **\n");
    exit(1);
  }

  pthread_mutex_lock(&q->lock);
}


void unlock_queue(Queue *q) {
  if (! q || q->magic != QUEUE_MAGIC) {
    fprintf(stderr,
            "** QUEUE NOT INITIALIZED in prioque.c unlock_queue() **\n");
    exit(1);
  }

  pthread_mutex_unlock(&q->lock);
}

