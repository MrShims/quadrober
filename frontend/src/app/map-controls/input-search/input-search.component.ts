import { Component, OnDestroy, OnInit, Optional } from '@angular/core';
import { NgbTypeahead } from '@ng-bootstrap/ng-bootstrap';
import { FormGroupDirective, ReactiveFormsModule } from '@angular/forms';
import { FeatureMember } from '../../models/geocoder-response';
import { debounceTime, filter, map, mergeMap, Observable, of, OperatorFunction, Subject, takeUntil } from 'rxjs';
import { MapService, MapState } from '../../services/map.service';
import { LngLat } from 'ymaps3';
import { PointForm } from '../map/map.component';
import { JsonPipe, NgIf } from '@angular/common';
import { Nullable } from '../../models/nullable';
import { Address } from '../../models/meeting/address';

@Component({
  selector: 'app-input-search',
  standalone: true,
  imports: [
    NgbTypeahead,
    ReactiveFormsModule,
    NgIf,
    JsonPipe
  ],
  templateUrl: './input-search.component.html',
  styleUrl: './input-search.component.scss',
})
export class InputSearchComponent implements OnDestroy, OnInit {
  form: Nullable<PointForm> = null;
  private readonly unsubscribe$ = new Subject<null>();
  search: OperatorFunction<string, readonly Address[]> = (text$: Observable<string>) =>
    text$.pipe(
      debounceTime(1000),
      filter((address) => !!address && !!address.trim().length),
      mergeMap((term) => {
        return term ? this.mapService.getCoordinatesByAddress(term) : of(null);
      }),
      map(items => {
        if (items) {
          return items || [];
        } else {
          return [];
        }
      }),
    );

  formatter = (x: Address) => {
    if (x) {
      return `${x?.name}`
    } else {
      return ''
    }
  };

  constructor(
    private readonly mapService: MapService,
    @Optional() private readonly formGroupDirective: FormGroupDirective,
  ) {
  }

  ngOnInit() {
    this.form = this.formGroupDirective.control;

    this.mapService.preparedCoordinates$
      .pipe(
        takeUntil(this.unsubscribe$),
      )
      .subscribe(response => {
        this.form?.controls.address.patchValue(response, { emitEvent: false });
      });

    this.form.controls.address.valueChanges.pipe(
      debounceTime(300),
      filter(address => !!address),
      takeUntil(this.unsubscribe$),
    ).subscribe(address => {
      if (address) {
        this.mapService.addPointFromInput(address.point as LngLat);
      }
    })
  }

  ngOnDestroy() {
    this.unsubscribe$.next(null);
    this.unsubscribe$.complete();
  }

  goNext() {
    this.mapService.setMapState(MapState.FILLING_FORM_DATETIME);
    if (this.form) {
      this.mapService.addPoint({
        // Ставим точно такую же точку на тех же координатах, только которую нельзя двигать
        coordinates: this.form.value.address?.point as LngLat,
        draggable: false,
      });
    }
  }

  cancelForm() {
    this.form?.reset();
    this.mapService.removeMeetingPoint();
    this.mapService.setMapState(MapState.INITIAL);
  }
}
