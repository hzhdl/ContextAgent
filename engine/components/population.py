#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from symbol import func_body_suite


class Individuals(object):
    '''
    Descriptor for all individuals in population.
    '''
    def __init__(self, name):
        self.name = '_{}'.format(name)

    def __get__(self, instance, owner):
        return instance.__dict__[self.name]

    def __set__(self, instance, value):
        instance.__dict__[self.name] = value
        # Update flag.
        instance.update_flag()

class Population(object):
    # All individuals.
    individuals = Individuals('individuals')
    seed_function_list = []
    funname2hash = {}

    def __init__(self, indv_template, indv_generator, size=100):
        '''
        Class for representing population in genetic algorithm.

        :param indv_template: A template individual to clone all the other
                              individuals in current population.

        :param size: The size of population, number of individuals in population.
        :type size: int

        '''
        # Population size.
        if size % 2 != 0:
            # raise ValueError('Population size must be an even number')
            size += 1
        self.size = size

        # Template individual.
        self.indv_template = indv_template

        # Generator individual.
        self.indv_generator = indv_generator

        # Container for all individuals - list-based for population
        self._individuals = []

        # Elite archive replaces seed pool (max 2000, sorted by fitness)
        self.elite_archive = []  # List of (individual, fitness) tuples

        # Update flag for tracking population changes
        self._updated = False

    def update_flag(self):
        '''
        Update flag to indicate population has been modified.
        Called automatically when individuals are set via the descriptor.
        '''
        self._updated = True

    def addlist(self,pre_tx_list,funname2hash):
        IndvType = self.indv_template.__class__
        for fa in pre_tx_list:
            
            tmp_list = []
            for tx in fa:
                if funname2hash and  "constructor" not in funname2hash and tx == "constructor":
                    continue
                tmp_list.append(funname2hash[tx])
            self.seed_function_list.extend([tmp_list])
        
        for function_list in self.seed_function_list:
            indv = IndvType(generator=self.indv_generator).init(
                self.indv_generator.generate_individual_By_Functionlist(function_list)
            )
            self._individuals.append(indv)  

    def init(self, seed_function_list, funname2hash, indvs=None):
        '''
        Initialize current population with individuals.

        :param indvs: Initial individuals in population, randomly initialized
                      individuals are created if not provided.
        :type indvs: list of Individual object
        '''
        IndvType = self.indv_template.__class__

        # Store these for population reset
        self.seed_function_list = seed_function_list
        self.funname2hash = funname2hash

        if indvs is None:
            if seed_function_list is None or seed_function_list == []:
                # Random seed generation
                while len(self._individuals) < self.size:
                    indv = IndvType(generator=self.indv_generator).init()
                    self._individuals.append(indv)  # Changed from enqueue
            else:
                # Targeted seed generation (CRITICAL - preserves requirement-based fuzzing)
                for function_list in seed_function_list:
                    indv = IndvType(generator=self.indv_generator).init(
                        self.indv_generator.generate_individual_By_Functionlist(function_list, funname2hash)
                    )
                    self._individuals.append(indv)  # Changed from enqueue

                # Fill to population size with random individuals if needed
                while len(self._individuals) < self.size:
                    indv = IndvType(generator=self.indv_generator).init()
                    self._individuals.append(indv)
        else:
            # Direct assignment for provided individuals
            if len(indvs) != self.size:
                raise ValueError('Invalid individuals number')
            self._individuals = indvs

        return self

    def init_hash(self, seed_function_list=None, indvs=None):
        '''
        Initialize current population with individuals.

        :param indvs: Initial individuals in population, randomly initialized
                      individuals are created if not provided.
        :type indvs: list of Individual object
        '''
        IndvType = self.indv_template.__class__

        # Store these for population reset
        if seed_function_list:
            self.seed_function_list = seed_function_list
        else:
            seed_function_list = self.seed_function_list

        if indvs is None:
            if seed_function_list is None or seed_function_list == []:
                # Random seed generation
                while len(self._individuals) < self.size:
                    indv = IndvType(generator=self.indv_generator).init()
                    self._individuals.append(indv)  # Changed from enqueue
            else:
                # Targeted seed generation (CRITICAL - preserves requirement-based fuzzing)
                for function_list in seed_function_list:
                    indv = IndvType(generator=self.indv_generator).init(
                        self.indv_generator.generate_individual_By_Functionlist(function_list)
                    )
                    self._individuals.append(indv)  # Changed from enqueue

                # Fill to population size with random individuals if needed
                while len(self._individuals) < self.size:
                    indv = IndvType(generator=self.indv_generator).init()
                    self._individuals.append(indv)
        else:
            # Direct assignment for provided individuals
            if len(indvs) != self.size:
                raise ValueError('Invalid individuals number')
            self._individuals = indvs

        return self
    
    def pre_init(self, indvs=None):
        '''
        Initialize current population with individuals.

        :param indvs: Initial individuals in population, randomly initialized
                      individuals are created if not provided.
        :type indvs: list of Individual object
        '''
        IndvType = self.indv_template.__class__

        if indvs is None:
            while len(self._individuals) < self.size:
                indv = IndvType(generator=self.indv_generator).init()
                self._individuals.append(indv)  # Changed from enqueue
        else:
            # Direct assignment
            if len(indvs) != self.size:
                raise ValueError('Invalid individuals number')
            self._individuals = indvs

        return self

    def add_to_archive(self, indv, fitness):
        '''
        Add individual to elite archive (max 2000, sorted by fitness).

        :param indv: Individual to add
        :param fitness: Fitness value of the individual
        '''
        from utils import settings
        max_archive_size = getattr(settings, 'ELITE_ARCHIVE_SIZE', 2000)

        # Add to archive
        self.elite_archive.append((indv, fitness))

        # Sort by fitness (descending) and keep top max_archive_size
        self.elite_archive.sort(key=lambda x: x[1], reverse=True)
        if len(self.elite_archive) > max_archive_size:
            self.elite_archive = self.elite_archive[:max_archive_size]

    def get_elite_seeds(self, n):
        '''
        Return top-n seeds from archive for reinjection.

        :param n: Number of elite seeds to return
        :return: List of individuals
        '''
        # Return top n individuals from elite archive
        return [indv for indv, _ in self.elite_archive[:n]]

    def insert_individuals(self, fitness_func=None):
        '''
        Insert targeted individuals based on dependency analysis.
        In population-based system, adds new seeds to the population.
        This is typically called during symbolic execution to inject new seeds.

        :param fitness_func: Optional fitness function to determine which individuals to replace
        '''
        if not self.seed_function_list or not self.funname2hash:
            return  # No targeted seeds to insert

        IndvType = self.indv_template.__class__

        # Generate targeted individuals based on function lists
        new_individuals = []
        for function_list in self.seed_function_list:
            try:
                indv = IndvType(generator=self.indv_generator).init(
                    self.indv_generator.generate_individual_By_Functionlist(
                        function_list, self.funname2hash
                    )
                )
                new_individuals.append(indv)
            except Exception:
                # Skip if generation fails
                continue

        if not new_individuals:
            return

        # Limit number of seeds to insert (max 5)
        num_to_insert = min(len(new_individuals), 5)
        seeds_to_insert = new_individuals[:num_to_insert]

        # Strategy 1: If population is empty or small, just append
        if len(self.individuals) < self.size:
            for seed in seeds_to_insert:
                if len(self.individuals) < self.size:
                    self.individuals.append(seed)
            return

        # Strategy 2: Replace worst individuals if fitness function provided
        if fitness_func:
            try:
                # Sort individuals by fitness (ascending - worst first)
                sorted_indices = sorted(
                    range(len(self.individuals)),
                    key=lambda i: fitness_func(self.individuals[i])
                )
                # Replace worst individuals
                for i in range(min(num_to_insert, len(sorted_indices))):
                    self.individuals[sorted_indices[i]] = seeds_to_insert[i]
                return
            except Exception:
                # If fitness calculation fails, fall back to strategy 3
                pass

        # Strategy 3: Replace random individuals (fallback)
        import random
        for seed in seeds_to_insert:
            if self.individuals:
                replace_idx = random.randint(0, len(self.individuals) - 1)
                self.individuals[replace_idx] = seed


    def new(self):
        '''
        Create a new emtpy population.
        '''
        return self.__class__(indv_template=self.indv_template, size=self.size)

    def __getitem__(self, key):
        '''
        Get individual by index.
        '''
        if key < 0 or key >= self.size:
            raise IndexError('Individual index({}) out of range'.format(key))
        return self.individuals[key]

    def __len__(self):
        '''
        Get length of population.
        '''
        return len(self.individuals)

    def best_indv(self, fitness):
        '''
        The individual with the best fitness.
        '''
        if not self.individuals:
            return None
        all_fits = self.all_fits(fitness)
        return max(zip(self.individuals, all_fits), key=lambda x: x[1])[0]

    def worst_indv(self, fitness):
        '''
        The individual with the worst fitness.
        '''
        if not self.individuals:
            return None
        all_fits = self.all_fits(fitness)
        return min(zip(self.individuals, all_fits), key=lambda x: x[1])[0]

    def max(self, fitness):
        '''
        Get the maximum fitness value in population.
        '''
        return max(self.all_fits(fitness))

    def min(self, fitness):
        '''
        Get the minimum value of fitness in population.
        '''
        return min(self.all_fits(fitness))

    def mean(self, fitness):
        '''
        Get the average fitness value in population.
        '''
        all_fits = self.all_fits(fitness)
        return sum(all_fits)/len(all_fits)

    def all_fits(self, fitness):
        '''
        Get all fitness values in population.
        '''
        return [fitness(indv) for indv in self.individuals]
