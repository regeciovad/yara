/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include <yara/arena.h>
#include <yara/ahocorasick.h>
#include <yara/error.h>
#include <yara/utils.h>
#include <yara/mem.h>



typedef struct _QUEUE_NODE
{
  YR_AC_STATE* value;

  struct _QUEUE_NODE*  previous;
  struct _QUEUE_NODE*  next;

} QUEUE_NODE;


typedef struct _QUEUE
{
  QUEUE_NODE* head;
  QUEUE_NODE* tail;

} QUEUE;


//
// _yr_ac_queue_push
//
// Pushes a state in a queue.
//
// Args:
//    QUEUE* queue     - The queue
//    YR_AC_STATE* state  - The state
//
// Returns:
//    ERROR_SUCCESS if succeed or the corresponding error code otherwise.
//

static int _yr_ac_queue_push(
    QUEUE* queue,
    YR_AC_STATE* value)
{
  QUEUE_NODE* pushed_node;

  pushed_node = (QUEUE_NODE*) yr_malloc(sizeof(QUEUE_NODE));

  if (pushed_node == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  pushed_node->previous = queue->tail;
  pushed_node->next = NULL;
  pushed_node->value = value;

  if (queue->tail != NULL)
    queue->tail->next = pushed_node;
  else // queue is empty
    queue->head = pushed_node;

  queue->tail = pushed_node;

  return ERROR_SUCCESS;
}


//
// _yr_ac_queue_pop
//
// Pops a state from a queue.
//
// Args:
//    QUEUE* queue     - The queue
//
// Returns:
//    Pointer to the poped state.
//

static YR_AC_STATE* _yr_ac_queue_pop(
    QUEUE* queue)
{
  YR_AC_STATE* result;
  QUEUE_NODE* popped_node;

  if (queue->head == NULL)
    return NULL;

  popped_node = queue->head;
  queue->head = popped_node->next;

  if (queue->head)
    queue->head->previous = NULL;
  else // queue is empty
    queue->tail = NULL;

  result = popped_node->value;

  yr_free(popped_node);
  return result;
}


//
// _yr_ac_queue_is_empty
//
// Checks if a queue is empty.
//
// Args:
//    QUEUE* queue     - The queue
//
// Returns:
//    true if queue is empty, false otherwise.
//

static int _yr_ac_queue_is_empty(
    QUEUE* queue)
{
  return queue->head == NULL;
}


//
// _yr_ac_next_state
//
// Given an automaton state and an input symbol, returns the new state
// after reading the input symbol.
//
// Args:
//    YR_AC_STATE* state     - Automaton state
//    uint8_t input       - Input symbol
//
// Returns:
//   Pointer to the next automaton state.
//

static YR_AC_STATE* _yr_ac_next_state(
    YR_AC_STATE* state,
    uint8_t input)
{
  YR_AC_STATE* next_state = state->first_child;

  while (next_state != NULL)
  {
    if (next_state->input == input)
      return next_state;

    next_state = next_state->siblings;
  }

  return NULL;
}


//
// _yr_ac_bitmap_common
//
// Returns true if the bitmap for states s2 and s1 have common symbols.
//

static bool _yr_ac_bitmap_common(
    YR_BITMASK bitmap1[YR_BITMAP_SIZE],
    YR_BITMASK bitmap2[YR_BITMAP_SIZE])
{
  int i;
  for (i = 0; i < YR_BITMAP_SIZE; i++)
  {
    if (bitmap1[i] & bitmap2[i])
      return true;
  }
  return false;
}


//
// _yr_ac_next_state_bitmap
//
// Given an automaton state and an input bitmap, returns the new state
// after reading the input bitmap.
//
// Args:
//    YR_AC_STATE* state     - Automaton state
//    YR_AC_STATE* state2     - Automaton state with input
//
// Returns:
//   Pointer to the next automaton state.
//
static YR_AC_STATE* _yr_ac_next_state_bitmap(
    YR_AC_STATE* state,
    YR_AC_STATE* state2)
{
  YR_AC_STATE* next_state = state->first_child;

  while (next_state != NULL)
  {
    if (next_state->type == YR_ATOM_TYPE_ANY)
      return next_state;
    else if (state2->type == YR_ATOM_TYPE_LITERAL)
    {
      if (yr_bitmask_isset(next_state->bitmap, state2->input))
        return next_state;
    }
    else
    {
      if (_yr_ac_bitmap_common(next_state->bitmap, state2->bitmap))
        return next_state;
    }

    next_state = next_state->siblings;
  }

    return NULL;
}


//
// _yr_ac_state_create
//
// Creates a new automaton state, the automaton will transition from
// the given state to the new state after reading the input symbol.
//
// Args:
//   YR_AC_STATE* state  - Origin state
//   uint8_t input       - Input symbol
//   YR_BITMASK bitmap[YR_BITMAP_SIZE]      Input symbols coded in bitmap
//
// Returns:
//   YR_AC_STATE* pointer to the newly allocated state or NULL in case
//   of error.

static YR_AC_STATE* _yr_ac_state_create(
    YR_AC_STATE* state,
    uint8_t input,
    YR_BITMASK bitmap[YR_BITMAP_SIZE],
    uint8_t type)
{
  YR_AC_STATE* new_state = (YR_AC_STATE*) yr_malloc(sizeof(YR_AC_STATE));

  if (new_state == NULL)
    return NULL;

  new_state->input = input;
  memcpy(new_state->bitmap, bitmap, (sizeof(YR_BITMASK) * YR_BITMAP_SIZE));
  new_state->type = type;
  new_state->depth = state->depth + 1;
  new_state->matches = NULL;
  new_state->failure = NULL;
  new_state->t_table_slot = 0;
  new_state->first_child = NULL;
  new_state->siblings = state->first_child;
  state->first_child = new_state;

  return new_state;
}


//
// _yr_ac_state_destroy
//

static int _yr_ac_state_destroy(
    YR_AC_STATE* state)
{
  YR_AC_STATE* child_state = state->first_child;

  while (child_state != NULL)
  {
    YR_AC_STATE* next_child_state = child_state->siblings;
    _yr_ac_state_destroy(child_state);
    child_state = next_child_state;
  }

  yr_free(state);

  return ERROR_SUCCESS;
}


//
// _yr_ac_copy_path
//
// Creates a copy of subpart of AC automaton starting with state `path` into `new_path`.
// If given `input_char`, it rewrites the input of the state `path` with it.
// Example:
//   o - a - b - c
//    |- d - e - f
//    _yr_ac_copy_path(d, o, k)
//   o - a - b - c
//    |- d - e - f
//    |- k - e - f

static YR_AC_STATE* _yr_ac_copy_path(
  YR_AC_STATE* path,
  YR_AC_STATE* new_path,
  YR_AC_STATE* input_state)
{

  YR_AC_STATE* state;
  YR_AC_STATE* current_state = new_path;
  YR_AC_STATE* new_state = NULL;

  YR_AC_MATCH* match;

  bool add_matches = false;

  // "root" node
  if (path != NULL)
  {
    if (input_state != NULL)
      new_state = _yr_ac_next_state(current_state, input_state->input);
    else
      new_state = _yr_ac_next_state(current_state, path->input);

    if (new_state == NULL)
    {
      if (input_state != NULL)
        new_state = _yr_ac_state_create(current_state, input_state->input, input_state->bitmap, input_state->type);
      else
        new_state = _yr_ac_state_create(current_state, path->input, path->bitmap, path->type);
    }

    if (new_state->matches == NULL)
      new_state->matches = path->matches;
    else
    {
      match = new_state->matches;

      add_matches = true;
      while (match != NULL)
      {
        if (match == path->matches)
        {
          add_matches = false;
          break;
        }

        if (match->next == NULL)
          break;

        match = match->next;
      }
      if (add_matches)
        match->next = path->matches;
    }

    current_state = new_state;
    state = path->first_child;

    while (state != NULL)
    {
      _yr_ac_copy_path(state, current_state, NULL);
      state = state->siblings;
    }
  }
  return new_state;
}


//
// _yr_ac_create_dac
//
// Create deterministic version of automaton. This function must
// be called before _yr_ac_create_failure_links.
//

static int _yr_ac_create_dac(
  YR_AC_AUTOMATON* automaton)
{
  int result = ERROR_SUCCESS;

  YR_STATE_LIST_ITEM* state_list[YR_MAX_ATOM_LENGTH] = { NULL };
  YR_STATE_LIST_ITEM* states = NULL;
  YR_STATE_LIST_ITEM* item = NULL;
  YR_STATE_LIST_ITEM* new_item = NULL;

  YR_AC_STATE* root_state = automaton->root;
  YR_AC_STATE* state = root_state->first_child;
  YR_AC_STATE* new_state = NULL;

  int i, j;
  int index = 0;

  while (state != NULL)
  {
    item = (YR_STATE_LIST_ITEM*)yr_malloc(sizeof(YR_STATE_LIST_ITEM));

    if (item == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    item->state = state;
    item->parent = root_state;
    item->next = NULL;

    if (state_list[0] != NULL)
    {
      item->next = state_list[0];
      state_list[0] = item;
    }
    else
    {
      state_list[0] = item;
    }

    state = state->siblings;
  }

  for (i = 0; i < YR_MAX_ATOM_LENGTH; i++)
  {
    states = state_list[i];
    while (states != NULL)
    {
      if (states->state->type == YR_ATOM_TYPE_ANY)
      {
        for (j = 0; j < i + 1; j++)
        {
          item = state_list[j];
          while (item != NULL)
          {
            if (item->state->type == YR_ATOM_TYPE_LITERAL)
            {
              if (yr_bitmask_isset(states->state->bitmap, item->state->input))
              {
                new_state = _yr_ac_copy_path(states->state, states->parent, item->state);
                yr_bitmask_clear(states->state->bitmap, item->state->input);
                states->state->type = YR_ATOM_TYPE_CLASS;

                new_item = (YR_STATE_LIST_ITEM*)yr_malloc(sizeof(YR_STATE_LIST_ITEM));

                if (item == NULL)
                  return ERROR_INSUFFICIENT_MEMORY;

                new_item->state = new_state;
                new_item->parent = states->parent;
                new_item->next = states->next;
                states->next = new_item;
              }
            }
            item = item->next;
          }
        }
      }

      state = states->state->first_child;

      while (state != NULL)
      {
        item = (YR_STATE_LIST_ITEM*)yr_malloc(sizeof(YR_STATE_LIST_ITEM));

        if (item == NULL)
          return ERROR_INSUFFICIENT_MEMORY;

        item->state = state;
        item->parent = states->state;
        item->next = NULL;
        index = state->depth - 1;

        if (state_list[index] != NULL)
        {
          item->next = state_list[index];
          state_list[index] = item;
        }
        else
        {
          state_list[index] = item;
        }
        state = state->siblings;
      }

      states = states->next;
    }
  }


  for (i = 0; i < YR_MAX_ATOM_LENGTH; i++)
  {
    states = state_list[i];
    while (states != NULL)
    {
      item = states->next;
      yr_free(states);
      states = item;
    }
  }
  return result;
}


//
// _yr_ac_create_failure_links
//
// Create failure links for each automaton state. This function must
// be called after all the strings have been added to the automaton.
//

static int _yr_ac_create_failure_links(
    YR_AC_AUTOMATON* automaton)
{
  YR_AC_STATE* current_state;
  YR_AC_STATE* failure_state;
  YR_AC_STATE* temp_state;
  YR_AC_STATE* state;
  YR_AC_STATE* transition_state;
  YR_AC_STATE* root_state;
  YR_AC_MATCH* match;

  bool add_matches = false;

  QUEUE queue;

  queue.head = NULL;
  queue.tail = NULL;

  root_state = automaton->root;

  // Set the failure link of root state to itself.
  root_state->failure = root_state;

  // Push root's children and set their failure link to root.
  state = root_state->first_child;

  while (state != NULL)
  {
    FAIL_ON_ERROR(_yr_ac_queue_push(&queue, state));
    state->failure = root_state;
    state = state->siblings;
  }

  // Traverse the trie in BFS order calculating the failure link
  // for each state.

  while (!_yr_ac_queue_is_empty(&queue))
  {
    current_state = _yr_ac_queue_pop(&queue);

    match = current_state->matches;

    if (match != NULL)
    {
      add_matches = true;
      while (match->next != NULL)
      {
        if (match == root_state->matches || match->next == root_state->matches)
        {
          add_matches = false;
          break;
        }
        match = match->next;
      }

      if (add_matches && match->backtrack > 0)
        match->next = root_state->matches;
    }
    else
    {
      current_state->matches = root_state->matches;
    }

    transition_state = current_state->first_child;

    while (transition_state != NULL)
    {
      FAIL_ON_ERROR(_yr_ac_queue_push(&queue, transition_state));
      failure_state = current_state->failure;

      while (1)
      {
        temp_state = _yr_ac_next_state_bitmap(
            failure_state, transition_state);

        if (temp_state != NULL)
        {
          transition_state->failure = temp_state;

          if (transition_state->matches == NULL)
          {
            transition_state->matches = temp_state->matches;
          }
          else
          {
            match = transition_state->matches;

            add_matches = true;
            while (match != NULL && match->next != NULL)
            {
              if (match == temp_state->matches || match->next == temp_state->matches)
              {
                add_matches = false;
                break;
              }

              match = match->next;
            }

            if (add_matches)
              match->next = temp_state->matches;
          }

          break;
        }
        else
        {
          if (failure_state == root_state)
          {
            transition_state->failure = root_state;
            break;
          }
          else
          {
            failure_state = failure_state->failure;
          }
        }
      } // while(1)

      transition_state = transition_state->siblings;
    }

  } // while(!__yr_ac_queue_is_empty(&queue))

  return ERROR_SUCCESS;
}


//
// _yr_ac_transitions_subset
//
// Returns true if the transitions for state s2 are a subset of the transitions
// for state s1. In other words, if at state s2 input X is accepted, it must be
// accepted in s1 too.
//

static bool _yr_ac_transitions_subset(
    YR_AC_STATE* s1,
    YR_AC_STATE* s2)
{
  YR_BITMASK set[YR_BITMAP_SIZE];

  YR_AC_STATE* state;
  int i;

  yr_bitmask_clear_all(set);

  state = s1->first_child;
  while (state != NULL)
  {
    if (state->type == YR_ATOM_TYPE_LITERAL)
    {
       yr_bitmask_set(set, state->input);
    }
    else
    {
      for (i = 0; i < YR_BITMAP_SIZE; i++)
        set[i] |= state->bitmap[i];
    }

    state = state->siblings;
  }

  state = s2->first_child;
  while (state != NULL)
  {
    if (state->type == YR_ATOM_TYPE_LITERAL)
    {
      if (!yr_bitmask_isset(set, state->input))
        return false;
    }
    else
    {
      for (i = 0; i < YR_BITMAP_SIZE; i++)
      {
        if ((set[i] & state->bitmap[i]) != state->bitmap[i])
          return false;
      }
    }
    state = state->siblings;
  }

  return true;
}

//
// _yr_ac_optimize_failure_links
//
// Removes unnecessary failure links.
//

static int _yr_ac_optimize_failure_links(
    YR_AC_AUTOMATON* automaton)
{
  QUEUE queue = { NULL, NULL};

  // Push root's children.
  YR_AC_STATE* root_state = automaton->root;
  YR_AC_STATE* state = root_state->first_child;

  while (state != NULL)
  {
    FAIL_ON_ERROR(_yr_ac_queue_push(&queue, state));
    state = state->siblings;
  }

  while (!_yr_ac_queue_is_empty(&queue))
  {
    YR_AC_STATE* current_state = _yr_ac_queue_pop(&queue);

    if (current_state->failure != root_state)
    {
      if (_yr_ac_transitions_subset(current_state, current_state->failure))
        current_state->failure = current_state->failure->failure;
    }

    // Push childrens of current_state
    state = current_state->first_child;

    while (state != NULL)
    {
      FAIL_ON_ERROR(_yr_ac_queue_push(&queue, state));
      state = state->siblings;
    }
  }

  return ERROR_SUCCESS;
}


//
// _yr_ac_find_suitable_transition_table_slot
//
// Find a place within the automaton's transition table where the transitions
// for the given state can be put. The function first create a bitmask for the
// state's transition table, then searches for an offset within the automaton's
// bitmask where the state's bitmask can be put without bit collisions.
//

static int _yr_ac_find_suitable_transition_table_slot(
    YR_AC_AUTOMATON* automaton,
    YR_AC_STATE* state,
    uint32_t* slot)
{
  // The state's transition table has 257 entries, 1 for the failure link and
  // 256 for each possible input byte, so the state's bitmask has 257 bits.
  YR_BITMASK state_bitmask[YR_BITMASK_SIZE(257)];

  int i, k;

  YR_AC_STATE* child_state = state->first_child;

  // Start with all bits set to zero.
  yr_bitmask_clear_all(state_bitmask);

  // The first slot in the transition table is for the state's failure link,
  // so the first bit in the bitmask must be set to one.
  yr_bitmask_set(state_bitmask, 0);

  while (child_state != NULL)
  {
    if (child_state->type == YR_ATOM_TYPE_LITERAL)
    {
      yr_bitmask_set(state_bitmask, child_state->input + 1);
    }
    else
    {
      for (i = 0; i < YR_BITMAP_SIZE; i++)
      {
        if (child_state->bitmap[i] != 0)
        {
          for (k = 0; k < YR_BITMASK_SLOT_BITS; k++)
          {
            if (yr_bitmask_isset(child_state->bitmap, i * YR_BITMASK_SLOT_BITS + k))
              yr_bitmask_set(state_bitmask, i * YR_BITMASK_SLOT_BITS + k + 1);
          }
        }
      }
    }
    child_state = child_state->siblings;
  }

  *slot = yr_bitmask_find_non_colliding_offset(
      automaton->bitmask,
      state_bitmask,
      automaton->tables_size,
      257,
      &automaton->t_table_unused_candidate);

  // Make sure that we are not going beyond the maximum size of the transition
  // table, starting at the slot found there must be at least 257 other slots
  // for accommodating the state's transition table.
  assert(*slot + 257 < YR_AC_MAX_TRANSITION_TABLE_SIZE);

  if (*slot > automaton->tables_size - 257)
  {
      size_t t_bytes_size = automaton->tables_size *
          sizeof(YR_AC_TRANSITION);

      size_t m_bytes_size = automaton->tables_size *
          sizeof(YR_AC_MATCH_TABLE_ENTRY);

      size_t b_bytes_size = YR_BITMASK_SIZE(automaton->tables_size) *
           sizeof(YR_BITMASK);

      automaton->t_table = (YR_AC_TRANSITION_TABLE) yr_realloc(
          automaton->t_table, t_bytes_size * 2);

      automaton->m_table = (YR_AC_MATCH_TABLE) yr_realloc(
          automaton->m_table, m_bytes_size * 2);

      automaton->bitmask = (YR_BITMASK*) yr_realloc(
          automaton->bitmask, b_bytes_size * 2);

      if (automaton->t_table == NULL ||
          automaton->m_table == NULL ||
          automaton->bitmask == NULL)
      {
        return ERROR_INSUFFICIENT_MEMORY;
      }

      memset((uint8_t*) automaton->t_table + t_bytes_size, 0, t_bytes_size);
      memset((uint8_t*) automaton->m_table + m_bytes_size, 0, m_bytes_size);
      memset((uint8_t*) automaton->bitmask + b_bytes_size, 0, b_bytes_size);

      automaton->tables_size *= 2;
  }

  return ERROR_SUCCESS;
}


//
// _yr_ac_build_transition_table
//
// Builds the transition table for the automaton. The transition table (T) is a
// large array of 32-bits integers. Each state in the automaton is represented
// by an index S within the array. The integer stored in T[S] is the failure
// link for state S, it contains the index of the next state when no valid
// transition exists for the next input byte.
//
// At position T[S+1+B] (where B is a byte) we can find the transition (if any)
// that must be followed from state S if the next input is B. The value in
// T[S+1+B] contains the index for next state or zero. A zero value means that
// no valid transition exists from state S when next input is B, and the failure
// link must be used instead.
//
// The transition table for state S starts at T[S] and spans the next 257
// slots in the array (1 for the failure link and 256 for all the possible
// transitions). But many of those slots are for invalid transitions, so
// the transitions for multiple states can be interleaved as long as they don't
// collide. For example, instead of having this transition table with state S1
// and S2 separated by a large number of slots:
//
// S1                                             S2
// +------+------+------+------+--   ~   --+------+------+------+--   ~   --+
// | FLS1 |   X  |   -  |   -  |     -     |  Y   | FLS2 |   Z  |     -     |
// +------+------+------+------+--   ~   --+------+------+------+--   ~   --+
//
// We can interleave the transitions for states S1 and S2 and get this other
// transition table, which is more compact:
//
// S1            S2
// +------+------+------+------+--   ~   --+------+
// | FLS1 |  X   | FLS2 |   Z  |     -     |  Y   |
// +------+------+------+------+--   ~   --+------+
//
// And how do we know that transition Z belongs to state S2 and not S1? Or that
// transition Y belongs to S1 and not S2? Because each slot of the array not
// only contains the index for the state where the transition points to, it
// also contains the offset of the transition relative to its owner state. So,
// the value for the owner offset would be 1 for transitions X, because X
// belongs to state S1 and it's located 1 position away from S1. The same occurs
// for Z, it belongs to S2 and it's located one position away from S2 so its
// owner offset is 1. If we are in S1 and next byte is 2, we are going to read
// the transition at T[S1+1+2] which is Z. But we know that transition Z is not
// a valid transition for state S1 because the owner offset for Z is 1 not 3.
//
// Each 32-bit slot in the transition table has 23 bits for storing the index
// of the target state and 9 bits for storing the offset of the slot relative
// to its own state. The offset can be any value from 0 to 256, both inclusive,
// hence 9 bits are required for it. The layout for the slot goes like:
//
// 32                      23        0
// +-----------------------+---------+
// | Target state's index  |  Offset |
// +-----------------------+---------+
//
// A more detailed description can be found in: http://goo.gl/lE6zG


static int _yr_ac_build_transition_table(
    YR_AC_AUTOMATON* automaton)
{
  YR_AC_STATE* state;
  YR_AC_STATE* child_state;
  YR_AC_STATE* root_state = automaton->root;

  uint32_t i, k;
  uint32_t num;
  uint32_t slot;
  uint32_t prev;
  uint32_t input;
  uint32_t input_slot;

  QUEUE queue = { NULL, NULL};

  automaton->tables_size = 1024;

  automaton->t_table = (YR_AC_TRANSITION_TABLE) yr_calloc(
      automaton->tables_size, sizeof(YR_AC_TRANSITION));

  automaton->m_table = (YR_AC_MATCH_TABLE) yr_calloc(
      automaton->tables_size, sizeof(YR_AC_MATCH_TABLE_ENTRY));

  automaton->bitmask = (YR_BITMASK*) yr_calloc(
      YR_BITMASK_SIZE(automaton->tables_size), sizeof(YR_BITMASK));

  if (automaton->t_table == NULL ||
      automaton->m_table == NULL ||
      automaton->bitmask == NULL)
  {
    yr_free(automaton->t_table);
    yr_free(automaton->m_table);
    yr_free(automaton->bitmask);

    return ERROR_INSUFFICIENT_MEMORY;
  }

  automaton->t_table[0] = YR_AC_MAKE_TRANSITION(0, 0);
  automaton->m_table[0].match = root_state->matches;

  yr_bitmask_set(automaton->bitmask, 0);

  // Index 0 is for root node. Unused indexes start at 1.
  automaton->t_table_unused_candidate = 1;

  child_state = root_state->first_child;

  while (child_state != NULL)
  {
    prev = 0;
    input_slot = 0;
    if (child_state->type == YR_ATOM_TYPE_LITERAL)
    {
      input_slot = child_state->input + 1;
      child_state->t_table_slot = input_slot;
      automaton->t_table[input_slot] = YR_AC_MAKE_TRANSITION(0, input_slot);
      automaton->t_table[input_slot] |= (prev << YR_AC_SLOT_OFFSET_BITS);
      prev = input_slot;
      yr_bitmask_set(automaton->bitmask, input_slot);
    }
    else
    {
      for (i = 0; i < YR_BITMAP_SIZE; i++)
      {
        if (child_state->bitmap[i] != 0)
        {
          for (k = 0; k < YR_BITMASK_SLOT_BITS; k++)
          {
            if (yr_bitmask_isset(child_state->bitmap, i * YR_BITMASK_SLOT_BITS + k))
            {
              input_slot = i * YR_BITMASK_SLOT_BITS + k + 1;
              child_state->t_table_slot = input_slot;
              automaton->t_table[input_slot] = YR_AC_MAKE_TRANSITION(0, input_slot);
              automaton->t_table[input_slot] |= (prev << YR_AC_SLOT_OFFSET_BITS);
              prev = input_slot;
              yr_bitmask_set(automaton->bitmask,input_slot);
            }
          }
        }
      }
    }
    FAIL_ON_ERROR(_yr_ac_queue_push(&queue, child_state));
    child_state = child_state->siblings;
  }


  while (!_yr_ac_queue_is_empty(&queue))
  {
    state = _yr_ac_queue_pop(&queue);

    FAIL_ON_ERROR(_yr_ac_find_suitable_transition_table_slot(
        automaton, state, &slot));

  // 511 = 1 1111 1111
    input = 0;
    prev = 0;
    do
    {
      input = (automaton->t_table[state->t_table_slot] & 511);
      prev = (automaton->t_table[state->t_table_slot] >> 9);
      automaton->t_table[state->t_table_slot] = input;
      automaton->t_table[state->t_table_slot] |= (slot << YR_AC_SLOT_OFFSET_BITS);
      state->t_table_slot = prev;
    } while (prev != 0);

    state->t_table_slot = slot;

    automaton->t_table[slot] = YR_AC_MAKE_TRANSITION(
        state->failure->t_table_slot, 0);

    yr_bitmask_set(automaton->bitmask, slot);

    automaton->m_table[slot].match = state->matches;

    // Push childrens of current_state

    child_state = state->first_child;

    while (child_state != NULL)
    {
      prev = 0;
      input_slot = 0;
      if (child_state->type == YR_ATOM_TYPE_LITERAL)
      {
        input_slot = child_state->input + 1;
        child_state->t_table_slot = slot + input_slot;
        automaton->t_table[child_state->t_table_slot] = YR_AC_MAKE_TRANSITION(0, input_slot);
        automaton->t_table[child_state->t_table_slot] |= (prev << YR_AC_SLOT_OFFSET_BITS);
        prev = child_state->t_table_slot;
        yr_bitmask_set(automaton->bitmask, child_state->t_table_slot);
      }
      else
      {
        for (i = 0; i < YR_BITMAP_SIZE; i++)
        {
          if (child_state->bitmap[i] != 0)
          {
            for (k = 0; k < YR_BITMASK_SLOT_BITS; k++)
            {
              if (yr_bitmask_isset(child_state->bitmap, i * YR_BITMASK_SLOT_BITS + k))
              {
                num = i * YR_BITMASK_SLOT_BITS + k + 1;
                child_state->t_table_slot = slot + num;
                automaton->t_table[child_state->t_table_slot] = YR_AC_MAKE_TRANSITION(0, num);
                automaton->t_table[child_state->t_table_slot] |= (prev << YR_AC_SLOT_OFFSET_BITS);
                prev = child_state->t_table_slot;
                yr_bitmask_set(automaton->bitmask, child_state->t_table_slot);
              }
            }
          }
        }
      }

      FAIL_ON_ERROR(_yr_ac_queue_push(&queue, child_state));
      child_state = child_state->siblings;
    }
  }

  return ERROR_SUCCESS;
}


//
// _yr_ac_print_automaton_state
//
// Prints automaton state for debug purposes. This function is invoked by
// yr_ac_print_automaton, is not intended to be used stand-alone.
//

static void _yr_ac_print_automaton_state(
    YR_AC_STATE* state)
{
  int i;
  int child_count;

  YR_AC_MATCH* match;
  YR_AC_STATE* child_state;

  for (i = 0; i < state->depth; i++)
    printf(" ");

  child_state = state->first_child;
  child_count = 0;

  while(child_state != NULL)
  {
    child_count++;
    child_state = child_state->siblings;
  }

  printf("%p childs:%d depth:%d failure:%p",
         state, child_count, state->depth, state->failure);

  match = state->matches;

  while (match != NULL)
  {
    printf("\n");

    for (i = 0; i < state->depth + 1; i++)
      printf(" ");

    printf("%s = ", match->string->identifier);

    if (STRING_IS_HEX(match->string))
    {
      printf("{ ");

      for (i = 0; i < yr_min(match->string->length, 10); i++)
        printf("%02x ", match->string->string[i]);

      printf("}");
    }
    else if (STRING_IS_REGEXP(match->string))
    {
      printf("/");

      for (i = 0; i < yr_min(match->string->length, 10); i++)
        printf("%c", match->string->string[i]);

      printf("/");
    }
    else
    {
      printf("\"");

      for (i = 0; i < yr_min(match->string->length, 10); i++)
        printf("%c", match->string->string[i]);

      printf("\"");
    }

    match = match->next;
  }

  printf("\n");

  child_state = state->first_child;

  while(child_state != NULL)
  {
    _yr_ac_print_automaton_state(child_state);
    child_state = child_state->siblings;
  }
}


//
// yr_ac_automaton_create
//
// Creates a new automaton
//

int yr_ac_automaton_create(
    YR_AC_AUTOMATON** automaton)
{
  YR_AC_AUTOMATON* new_automaton;
  YR_AC_STATE* root_state;

  new_automaton = (YR_AC_AUTOMATON*) yr_malloc(sizeof(YR_AC_AUTOMATON));
  root_state = (YR_AC_STATE*) yr_malloc(sizeof(YR_AC_STATE));

  if (new_automaton == NULL || root_state == NULL)
  {
    yr_free(new_automaton);
    yr_free(root_state);

    return ERROR_INSUFFICIENT_MEMORY;
  }

  root_state->depth = 0;
  root_state->matches = NULL;
  root_state->failure = NULL;
  root_state->first_child = NULL;
  root_state->siblings = NULL;
  root_state->t_table_slot = 0;

  new_automaton->root = root_state;
  new_automaton->m_table = NULL;
  new_automaton->t_table = NULL;
  new_automaton->bitmask = NULL;
  new_automaton->tables_size = 0;

  *automaton = new_automaton;

  return ERROR_SUCCESS;
}


//
// yr_ac_automaton_destroy
//
// Destroys automaton
//

int yr_ac_automaton_destroy(
    YR_AC_AUTOMATON* automaton)
{
  _yr_ac_state_destroy(automaton->root);

  yr_free(automaton->t_table);
  yr_free(automaton->m_table);
  yr_free(automaton->bitmask);
  yr_free(automaton);

  return ERROR_SUCCESS;
}


//
// yr_ac_add_string
//
// Adds a string to the automaton. This function is invoked once for each
// string defined in the rules.
//

int yr_ac_add_string(
    YR_AC_AUTOMATON* automaton,
    YR_STRING* string,
    YR_ATOM_LIST_ITEM* atom,
    YR_ARENA* matches_arena)
{
  int result = ERROR_SUCCESS;
  int i;

  YR_AC_STATE* state;
  YR_AC_STATE* next_state;
  YR_AC_MATCH* new_match;
  YR_AC_STATE* test_state;

  static YR_BITMASK bitmap_any_chars[YR_BITMAP_SIZE];
  yr_bitmask_clear_all(bitmap_any_chars);

  // For coding all symbols I need 256 bits, 4 * 8 bytes of unsigned long
  for (i = 0; i < YR_BITMAP_SIZE - 1; i++)
  {
    bitmap_any_chars[i] = ULONG_MAX;
  }

  YR_BITMASK bitmap[YR_BITMAP_SIZE];


  // For each atom create the states in the automaton.

  while (atom != NULL)
  {
    state = automaton->root;

    for (i = 0; i < atom->atom.length; i++)
    {
      switch (atom->atom.mask[i])
      {
        case YR_ATOM_TYPE_ANY:
          next_state = NULL;
          test_state = state->first_child;
          while (test_state != NULL)
          {
            if (test_state->type == YR_ATOM_TYPE_ANY)
            {
              next_state = test_state;
              break;
            }
            test_state = test_state->siblings;
          }
          if (next_state == NULL)
          {
            next_state = _yr_ac_state_create(state, atom->atom.bytes[i], bitmap_any_chars, atom->atom.mask[i]);
            if (next_state == NULL)
              return ERROR_INSUFFICIENT_MEMORY;
          }
          state = next_state;
          break;

        default:
          next_state = _yr_ac_next_state(state, atom->atom.bytes[i]);

          if (next_state == NULL)
          {
            yr_bitmask_clear_all(bitmap);
            yr_bitmask_set(bitmap, atom->atom.bytes[i]);
            next_state = _yr_ac_state_create(state, atom->atom.bytes[i], bitmap, atom->atom.mask[i]);

            if (next_state == NULL)
              return ERROR_INSUFFICIENT_MEMORY;
          }
          state = next_state;
          break;
      };
    }

    result = yr_arena_allocate_struct(
        matches_arena,
        sizeof(YR_AC_MATCH),
        (void**) &new_match,
        offsetof(YR_AC_MATCH, string),
        offsetof(YR_AC_MATCH, forward_code),
        offsetof(YR_AC_MATCH, backward_code),
        offsetof(YR_AC_MATCH, next),
        EOL);

    if (result == ERROR_SUCCESS)
    {
      new_match->backtrack = state->depth + atom->backtrack;
      new_match->string = string;
      new_match->forward_code = atom->forward_code;
      new_match->backward_code = atom->backward_code;
      new_match->next = state->matches;
      state->matches = new_match;
    }
    else
    {
      break;
    }

    atom = atom->next;
  }

  return result;
}


//
// yr_ac_compile
//

int yr_ac_compile(
    YR_AC_AUTOMATON* automaton,
    YR_ARENA* arena,
    YR_AC_TABLES* tables)
{
  uint32_t i;

  FAIL_ON_ERROR(_yr_ac_create_dac(automaton));
  FAIL_ON_ERROR(_yr_ac_create_failure_links(automaton));
  FAIL_ON_ERROR(_yr_ac_optimize_failure_links(automaton));
  FAIL_ON_ERROR(_yr_ac_build_transition_table(automaton));

  FAIL_ON_ERROR(yr_arena_reserve_memory(
      arena,
      automaton->tables_size * sizeof(tables->transitions[0]) +
      automaton->tables_size * sizeof(tables->matches[0])));

  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      automaton->t_table,
      sizeof(YR_AC_TRANSITION),
      (void**) &tables->transitions));

  for (i = 1; i < automaton->tables_size; i++)
  {
    FAIL_ON_ERROR(yr_arena_write_data(
        arena,
        automaton->t_table + i,
        sizeof(YR_AC_TRANSITION),
        NULL));
  }

  FAIL_ON_ERROR(yr_arena_write_data(
      arena,
      automaton->m_table,
      sizeof(YR_AC_MATCH_TABLE_ENTRY),
      (void**) &tables->matches));

  FAIL_ON_ERROR(yr_arena_make_ptr_relocatable(
      arena,
      tables->matches,
      offsetof(YR_AC_MATCH_TABLE_ENTRY, match),
      EOL));

  for (i = 1; i < automaton->tables_size; i++)
  {
    void* ptr;

    FAIL_ON_ERROR(yr_arena_write_data(
        arena,
        automaton->m_table + i,
        sizeof(YR_AC_MATCH_TABLE_ENTRY),
        (void**) &ptr));

    FAIL_ON_ERROR(yr_arena_make_ptr_relocatable(
        arena,
        ptr,
        offsetof(YR_AC_MATCH_TABLE_ENTRY, match),
        EOL));
  }

  return ERROR_SUCCESS;
}


//
// yr_ac_print_automaton
//
// Prints automaton for debug purposes.
//

void yr_ac_print_automaton(YR_AC_AUTOMATON* automaton)
{
  printf("-------------------------------------------------------\n");
  _yr_ac_print_automaton_state(automaton->root);
  printf("-------------------------------------------------------\n");
}
